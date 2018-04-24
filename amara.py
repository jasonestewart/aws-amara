import boto3
import re
from SESEmail import SESEmail
from datetime import datetime, timedelta
import logging
import json
from aiohttp import ClientSession, TCPConnector
import asyncio
# from IPython import embed

AWS_REGION = "us-east-1"
DB = boto3.resource("dynamodb", region_name=AWS_REGION)
BASE_URL = "https://amara.org"

module_logger = logging.getLogger('amara-handler.{}'.format(__name__))

class Amara(object):
    """Class for encapsulating Amara.org"""

    @classmethod
    def signup_for_job(cls, team_num):
        module_logger.info("Amara.signup_for_job: %s", 'start')

        loop = asyncio.get_event_loop()
        future = asyncio.ensure_future(cls.run_job_checks(team_num))
        loop.run_until_complete(future)

        module_logger.info("Amara.signup_for_job: %s", 'end')

    @classmethod
    async def run_job_checks(cls, team_num):
        module_logger.info("Amara.run_job_checks: %s", 'start')

        # Create client session that will ensure we dont open new connection
        # per each request.
        async with ClientSession(connector=TCPConnector(verify_ssl=False)) as session:
            await AmaraUser.init(session)
            user = AmaraUser()

            await user.signup_for_job(team_num)

        module_logger.info("Amara.run_job_checks: %s", 'end')
        

class AmaraTeam(object):
    """Class for encapsulating Teams on Amara.org"""

    TEAM_URL_TEMPLATE = BASE_URL + "/en/teams/{}/"

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<AmaraTeam: Name: {}>".format(self.name)

    @classmethod
    def get_slug(cls, team_name):
        return re.match(r".*(\d\d\d).*", team_name).group(1)


class AmaraJob(object):
    """Class for encapsulating new jobs on Amara.org"""

    def __init__(self):
        self.logger = logging.getLogger("amara-handler.{}.AmaraJob".format(__name__))

    def __cmp__(self, other):
        return self.duration.__cmp__(other.duration)

    def send_email(self, message):
        self.logger.info("send_email: %s", 'start')

        # await self.save_page(session)
        team = self.team
        url = team.TEAM_URL_TEMPLATE.format(team.name)

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
                   team_url=url)
        email.send_email()
        self.logger.info("send_email: %s", 'end')

    async def handle(self, type):
        self.logger.info("handle: %s", 'start')

        self.logger.debug("handle: self: %s", self)

        user = AmaraUser()
        result = await user.api_call_put(user.API_JOIN_TEMPLATE.format(self.team.name, self.job_id),
                                         {type: user.name})
        try:
            if result[type]['username'] == user.name:
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
        self.video = ''
        self.duration = 0
        self.logger = logging.getLogger("amara-handler.{}.AmaraReviewJob".format(__name__))

    def __repr__(self):
        return "<AmaraReviewJob: Team: {}, video: {}, duration: {}>\n".format(self.team,
                                                                              self.video,
                                                                              self.duration)

    async def handle(self):
        await super().handle('reviewer')


class AmaraTranscriptionJob(AmaraJob):
    """Class for encapsulating new transcription jobs on Amara.org"""

    def __init__(self, team, job_id):
        self.type = 'transcription'
        self.team = team
        self.job_id = job_id
        self.video = ''
        self.duration = 0
        self.logger = logging.getLogger("amara-handler.{}.AmaraTranscriptionJob".format(__name__))

    def __repr__(self):
        return "<AmaraTranscriptionJob: Team: {}, video: {}, duration: {}>\n".format(self.team,
                                                                                     self.video,
                                                                                     self.duration)

    async def handle(self):
        await super().handle('subtitler')


class AmaraUser(object):
    """Class for encapsulating Amara.org login"""

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

    async def fetch_teams_paged(self, offset):
        teams = 0
        p = {'limit': '20', 'offset': offset}
        async with self.__session.get(self.API_TEAMS_URL,
                                      params=p,
                                      headers=self.api_headers) as r:
            j = await r.json()
            for team in j['objects']:
                if re.search(r"demand.*\d\d\d", team['slug']):
                    t = AmaraTeam(team['slug'])
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
        user.teams_by_name = {}
        user.teams_by_number = {}
        for team in teams_list:
            user.teams_by_name[team.name] = team
            slug = AmaraTeam.get_slug(team.name)
            if not slug in user.teams_by_number:
                user.teams_by_number[slug] = [team]
            else:
                user.teams_by_number[slug].append(team)

        user.current_jobs = await user.fetch_current_jobs()
        module_logger.info("AmaraUser.init: %s", 'end')

    @staticmethod
    def get_db_user():
        module_logger.info("AmaraUser.__get_db_user: %s", 'start')
        user = DB.Table("user")
        response = user.get_item(Key={"service_name" : "amara"})
        module_logger.info("AmaraUser.__get_db_user: %s", 'end')
        return response["Item"]

    async def fetch_current_jobs(self):
        self.logger.info("fetch_current_jobs: %s", 'start')

        today = datetime.today()
        before = today - timedelta(days=5)

        url = self.API_USER_ACT_URL_TEMPLATE.format(self.name)
        url += "?after=" + before.strftime('%Y-%m-%d')
        jobs = await self.api_call(url)
        finished = {}
        current = []
        for job in jobs:
            if re.search(r"collab-unassign|collab-endorse|collab-leave", job['type']):
                self.logger.debug("fetch_current_jobs: finished job: %s", job['video'])
                finished[job['video']] = 1
            elif re.search(r"collab-join|collab-assign", job['type']) and not job['video'] in finished:
                self.logger.debug("fetch_current_jobs: open job: %s", job['video'])
                current.append(job)

        self.logger.debug("fetch_current_jobs: found %i job(s)", len(current))
        current_jobs = []
        for job in current:
            vid_info = await self.api_call(self.API_VIDEOS_TEMPLATE.format(job['video']), False)
            team_name = vid_info['team']
            slug = AmaraTeam.get_slug(team_name)
            current_jobs.append(slug)

        self.logger.info("fetch_current_jobs: end: found jobs: %s", current_jobs)
        return current_jobs

    async def signup_for_job(self, team_num):
        self.logger.info("signup_for_job: team: %s, start", team_num)

        if team_num in self.current_jobs:
            self.logger.info("signup_for_job: already have job for team: %s, end", team_num)
            return

        await self.find_all_team_jobs(team_num)
        if self.available_jobs:
            job = sorted(self.available_jobs).pop()
            await job.handle()

        self.logger.info("signup_for_job: team: %s, end", team_num)

    async def find_all_team_jobs(self, team_num):
        self.logger.info("check_for_new_jobs: start team: %s", team_num)

        teams = self.teams_by_number[team_num]
        for team in teams:
            jobs = await self.api_call(self.API_TEAM_JOB_URL_TEMPLATE.format(team.name))

            for job in jobs:
                if job['language'] == 'en':
                    new_job = None
                    if job['work_status'] == 'needs-subtitler':
                        self.logger.info("check_for_new_jobs: found available transcription job for team: %s", team.name)
                        new_job = AmaraTranscriptionJob(team, job['job_id'])
                    elif job['work_status'] == 'needs-reviewer':
                        self.logger.info("check_for_new_jobs: found available review job for team: %s", team.name)
                        new_job = AmaraReviewJob(team, job['job_id'])

                    if new_job:
                        video = await self.api_call(self.API_VIDEOS_TEMPLATE.format(job['video']),
                                                    False)
                        new_job.duration = video['duration']
                        new_job.video = job['video']
                        self.available_jobs.append(new_job)

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
                    self.logger.exception("api_call: url: %s, found json: %s", url, json.dumps(j))
                    raise
                ret_val = j['objects']
            else:
                ret_val = j

        return ret_val
