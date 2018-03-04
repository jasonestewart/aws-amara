import boto3
import re
from SESEmail import SESEmail
from datetime import datetime
from lxml import html
import logging
import json
import asyncio
# from IPython import embed

AWS_REGION = "us-east-1"
DB = boto3.resource("dynamodb", region_name=AWS_REGION)
BASE_URL = "https://amara.org"

module_logger = logging.getLogger('amara-handler.{}'.format(__name__))


class AmaraTeam(object):
    """Class for encapsulating Teams on Amara.org"""

    def __init__(self, name, url):
        self.name = name
        self.url = url

    def __repr__(self):
        return "<AmaraTeam: Name: {}, URL: {}>".format(self.name, self.url)


class AmaraJob(object):
    """Class for encapsulating new jobs on Amara.org"""

    LOCAL = False
    DEBUG = False

    def __init__(self):
        self.logger = logging.getLogger("amara-handler.{}.AmaraJob".format(__name__))

    def send_email(self, message):
        self.logger.info("send_email: %s", 'start')

        # await self.save_page(session)
        team = self.team

        email = SESEmail()
        email.subject = "Amara alert, type: {}, team: {}".format(self.type, team.name)
        email.body = """<html>
<head></head>
<body>
  <h1>Amara Alert: {type}</h1>
  <h2>Message</h2>
  <p>{msg}</p>
  <p>Action from team {team} requires your attention
    <a href='{team_url}'>{team_url}</a></p>
</body>
</html>
        """.format(team=team.name,
                   type=self.type,
                   msg=message,
                   team_url=team.url)
        email.send_email()
        self.logger.info("send_email: %s", 'end')

    async def handle(self, type):
        self.logger.info("handle: %s", 'start')

        self.logger.debug("handle: self: %s", self)

        user = AmaraUser()
        result = await user.api_call_put(user.API_JOIN_TEMPLATE.format(self.team.name, self.job_id),
                                   {type:user.name})
        try:
            if result[type]['username'] == user.name:
                user.add_new_job(self)
                self.send_email("successfully joined new job")
        except KeyError:
            self.logger.exception("handle: bad result: %s", result)

        self.logger.info("handle: %s", 'end')


class AmaraReviewJob(AmaraJob):
    """Class for encapsulating new review jobs on Amara.org"""

    def __init__(self, team, job_id):
        self.type = 'review'
        self.team = team
        self.job_id = job_id
        self.logger = logging.getLogger("amara-handler.{}.AmaraReviewJob".format(__name__))

    def __repr__(self):
        return "<AmaraReviewJob: Team: {}, URL: {}>\n".format(self.team, self.url)

    async def handle(self):
        await super().handle('reviewer')


class AmaraTranscriptionJob(AmaraJob):
    """Class for encapsulating new transcription jobs on Amara.org"""

    def __init__(self, team, job_id):
        self.type = 'transcription'
        self.team = team
        self.job_id = job_id
        self.logger = logging.getLogger("amara-handler.{}.AmaraTranscriptionJob".format(__name__))

    def __repr__(self):
        return "<AmaraTranscriptionJob: Team: {}, URL: {}>\n".format(self.team, self.url)

    async def handle(self):
        await super().handle('subtitler')


class AmaraUser(object):
    """Class for encapsulating Amara.org login"""

    LOCAL = False
    DEBUG = False

    API_URL        = BASE_URL + "/api"
    API_TEAMS_URL  = API_URL + "/teams/"
    API_USERS_URL  = API_URL + "/users/"
    API_VIDEOS_URL = API_URL + "/videos/"

    API_TEAM_JOB_URL_TEMPLATE = API_TEAMS_URL + "{}/subtitle-requests/"
    API_USER_ACT_URL_TEMPLATE = API_USERS_URL + "{}/activity/"
    API_VIDEOS_TEMPLATE       = API_VIDEOS_URL + "{}/"
    API_JOIN_TEMPLATE         = API_TEAM_JOB_URL_TEMPLATE + "{}/"

    __instance = None
    __session  = None
    ignore_teams = None

    def __init__(self):
        self.logger = logging.getLogger("amara-handler.{}.AmaraUser".format(__name__))
        self.logger.info("__init__: %s", 'end')

    def __new__(cls):
        module_logger.info("AmaraUser.__new__")
        if cls.__instance is None:
            module_logger.info("AmaraUser.__new__: %s", 'creating singleton')
            cls.__instance = object.__new__(cls)
            login = cls.get_db_user()
            cls.__instance.api_key = login['api_key']
            cls.__instance.name = login['user']
            cls.__instance.password = login['pass']
            cls.__instance.current_jobs = None
            cls.__instance.available_jobs = []
        return cls.__instance

    async def handle_jobs(self):
        self.logger.info("handle_jobs: %s", 'start')

        if not self.available_jobs:
            self.logger.info("handle_jobs: no available jobs: %s", 'exit')
            return

        def curr_job_filter(new, curr_jobs):
            result = list(filter(lambda curr: curr.team.name == new.team.name and curr.type == new.type,
                                 curr_jobs))
            return not result

        self.logger.debug("handle_jobs: available jobs: \n\t%s",
            "\n\t".join(map(str, self.available_jobs)))

        self.logger.debug("handle_jobs: current jobs: \n\t%s",
            "\n\t".join(map(str, self.get_current_jobs())))

        jobs = list(filter(lambda j: curr_job_filter(j, self.get_current_jobs()),
                           self.available_jobs))

        self.logger.info("handle_jobs: new jobs: \n\t%s",
            "\n\t".join(map(str, jobs)))

        for job in jobs:
            await job.handle()

        self.logger.info("handle_jobs: %s", 'end')

    async def fetch_teams_paged(self, offset):
        teams = 0
        p = {'limit': '20', 'offset': offset}
        async with self.__session.get(self.API_TEAMS_URL,
                                      params=p,
                                      headers=self.api_headers) as r:
            j = await r.json()
            for team in j['objects']:
                if re.search(r"demand.*\d\d\d", team['slug']):
                    t = AmaraTeam(team['slug'], team['activity_uri'])
                    teams += 1
                    self.teams_list.append(t)

        self.logger.debug("fetch_teams_paged: offset: %i, found %i OnDemand teams", offset, teams)

    async def bound_team_fetch(self, sem, offset):
        async with sem:
            return await self.fetch_teams_paged(offset)

    async def fetch_all_teams(self):
        self.logger.info("fetch_all_teams: %s", 'start')
        self.teams_list = []
        tasks = []
        sem = asyncio.Semaphore(20)
        for offset in range(0, 323, 20):
            task = asyncio.ensure_future(self.bound_team_fetch(sem, offset))
            tasks.append(task)

        # Gather all futures
        tasks = asyncio.gather(*tasks)
        await tasks

        self.logger.info("fetch_all_teams: %s", 'start')
        return self.teams_list

    @classmethod
    async def init(cls, session):
        module_logger.info("AmaraUser.init: %s", 'start')

        # I know this is weird but __new__ has to be called first
        user = AmaraUser()
        user.__session = session

        user.api_headers = {'X-api-key'      : user.api_key,
                            'X-api-username' : user.name,
        }
        teams_list = await user.fetch_all_teams()
        user.teams = {}
        for team in teams_list:
            user.teams[team.name] = team

        user.current_jobs = await user.fetch_current_jobs()
        user.ignore_teams = user.get_db_ignore_teams()
        module_logger.info("AmaraUser.init: %s", 'end')

    @staticmethod
    def get_db_ignore_teams():
        module_logger.info("AmaraUser.fetch_ignore_teams: %s", 'start')
        db_table = DB.Table("ignore_team")
        response = db_table.scan()
        teams = list(map(lambda r: r['team_name'], response["Items"]))
        module_logger.info("AmaraUser.fetch_ignore_teams:  found teams: %s", teams)
        return teams

    @staticmethod
    def get_db_user():
        module_logger.info("AmaraUser.__get_db_user: %s", 'start')
        user = DB.Table("user")
        response = user.get_item(Key={"service_name" : "amara"})
        module_logger.info("AmaraUser.__get_db_user: %s", 'end')
        return response["Item"]

    def add_new_job(self, job):
        self.logger.info("add_new_job: %s", 'start')
        if self.current_jobs is None:
            self.logger.error("add_new_job: called before current jobs set")
        else:
            self.current_jobs.append(job)
        self.logger.info("add_new_job: %s", 'end')

    def get_current_jobs(self):
        return self.current_jobs

    async def fetch_current_jobs(self):
        self.logger.info("fetch_current_jobs: %s", 'start')
        jobs = await self.api_call(self.API_USER_ACT_URL_TEMPLATE.format(self.name))
        finished = {}
        current = []
        for job in jobs:
            if re.search(r"collab-unassign|collab-endorse|collab-leave", job['type']):
                finished[job['video']] = 1
            elif re.search(r"collab-join|collab-assign", job['type']) and not job['video'] in finished:
                current.append(job)

        current_jobs = []
        if current:
            for job in current:
                vid_info = await self.api_call(self.API_VIDEOS_TEMPLATE.format(job['video']), False)
                team_name = vid_info['team']
                team = self.teams[team_name]
                sub_reqs = await self.api_call(self.API_TEAM_JOB_URL_TEMPLATE.format(team_name))
                for req in sub_reqs:
                    if req['video'] == job['video']:
                        if req['reviewer'] is not None and req['reviewer']['username'] == self.name:
                            current_jobs.append(AmaraReviewJob(team))
                        elif req['subtitler'] is not None and req['subtitler']['username'] == self.name:
                            current_jobs.append(AmaraTranscriptionJob(team))
                        else:
                            self.logger.error("fetch_current_jobs: couldn't find info for job: %s, req: %s", job, req)
                        break
                else:
                    self.logger.error("fetch_current_jobs: couldn't find info for job: %s, reqs: %s", job, sub_reqs)

        self.logger.info("fetch_current_jobs: end: found jobs: %s", current_jobs)
        return current_jobs

    async def save_page(self, root, team, reason):
        table = DB.Table('stored_pages')
        id = str(datetime.utcnow()) + team.name
        response = table.put_item(
           Item={
                'ID': id,
                'page': html.tostring(root),
                'url': team.url,
                'type': reason,
            }
        )

    async def check_for_new_jobs(self, team):

        if team.name in self.ignore_teams:
            self.logger.info("check_for_new_jobs: ignoring team: %s", team.name)
            return

        jobs = await self.api_call(self.API_TEAM_JOB_URL_TEMPLATE.format(team.name))

        for job in jobs:
            if job['language'] == 'en':
                if job['work_status'] == 'needs-subtitler':
                    self.logger.info("check_for_new_jobs: found available transcription job for team: %s", team.name)
                    self.available_jobs.append(AmaraTranscriptionJob(team, job['job_id']))
                elif job['work_status'] == 'needs-reviewer':
                    self.logger.info("check_for_new_jobs: found available review job for team: %s", team.name)
                    self.available_jobs.append(AmaraReviewJob(team, job['job_id']))

    async def api_call_put(self, url, json_data):
        self.logger.info("api_call_put: start, url: %s, data: %s", url, json_data)

        async with self.__session.put(url, headers=self.api_headers, data=json_data) as r:
            j = await r.json()

        self.logger.info("api_call_put: end, url: %s", url)
        return j
    

    async def api_call(self, url, list=True):
        self.logger.debug("api_call: start, url: %s", url)

        async with self.__session.get(url, headers=self.api_headers) as r:
            ret_val = None
            j = await r.json()
            if list:
                if 'objects' not in j:
                    self.logger.exception("check_for_new_jobs: team: %s, found json: %s", team.name, json.dumps(j))
                    raise
                ret_val = j['objects']
            else:
                ret_val = j

        return ret_val
