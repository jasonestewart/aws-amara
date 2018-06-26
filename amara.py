import boto3
import re
from SESEmail import SESEmail
from datetime import datetime, timedelta
import logging
import json
import os
from aiohttp import ClientSession, TCPConnector
import asyncio
from lxml import html
# from IPython import embed

AWS_REGION = "us-east-1"
DB = boto3.resource("dynamodb", region_name=AWS_REGION)
BASE_URL = "https://amara.org"

module_logger = logging.getLogger('amara-handler.{}'.format(__name__))


class Amara(object):
    """Class for encapsulating Amara.org"""

    @classmethod
    def signup_for_job(cls, team_name, link):
        module_logger.info("Amara.signup_for_job: %s", 'start')

        loop = asyncio.get_event_loop()
        future = asyncio.ensure_future(cls.run_job_checks(team_name, link))
        loop.run_until_complete(future)

        module_logger.info("Amara.signup_for_job: %s", 'end')

    @classmethod
    async def run_job_checks(cls, team_name, link):
        module_logger.info("Amara.run_job_checks: %s", 'start')

        # Create client session that will ensure we dont open new connection
        # per each request.
        async with ClientSession(connector=TCPConnector(verify_ssl=False)) as session:
            await AmaraUser.init(session)
            user = AmaraUser()

            await user.signup_for_job(team_name, link)

        module_logger.info("Amara.run_job_checks: %s", 'end')


class AmaraTeam(object):
    """Class for encapsulating Teams on Amara.org"""

    TEAM_URL_TEMPLATE = BASE_URL + "/en/teams/{}/"

    def __init__(self, name):
        self.name = name
        self.url = self.TEAM_URL_TEMPLATE.format(name)

    def __repr__(self):
        return "<AmaraTeam: Name: {}, URL: {}>".format(self.name, self.url)

    @classmethod
    def get_slug(cls, team_name):
        return re.search(r"(\d\d\d)", team_name).group(1)

    @classmethod
    def get_team_name_from_link(cls, link):
        match = re.search(r"/en/teams/([-\w]+)/assignments/", link)
        team_name = ''
        if match:
            team_name = match.group(1)
        return team_name


class AmaraJob(object):
    """Class for encapsulating new jobs on Amara.org"""

    def __init__(self):
        self.logger = logging.getLogger("amara-handler.{}.AmaraJob".format(__name__))

    def __cmp__(self, other):
        return self.duration.__cmp__(other.duration)

    def __lt__(self, other):
        return self.duration < other.duration

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

    async def handle(self, session):
        self.logger.info("handle: %s", 'start')

        self.logger.debug("handle: self: %s", self)

        if not self.url.startswith('http'):
            self.url = BASE_URL + self.url

        user = AmaraUser()
        ref = {'referer' : self.team.url}
        self.logger.debug("handle: using referer: %s", ref)

        async with session.get(self.url, headers=ref) as response:
            if response.status != 200:
                text = await response.text()
                self.logger.error("error while joining: %s, status: %s, headers: %s, text: %s",
                    self.url, response.status, response.headers, text)
                for cookie in session.cookie_jar:
                    self.logger.error("found cookie: %s", cookie)
            else:
                self.send_email("new job")
                self.logger.info("handle: join success, adding job: %s", self.job_id)

        self.logger.info("handle: %s", 'end')

    async def handle_api(self, session):
        self.logger.info("handle_api: %s", 'start')

        self.logger.debug("handle_api: self: %s", self)

        user = AmaraUser()
        api = AmaraAPI(session, user.api_key, user.name)
        result = await api.api_call_put(api.API_JOIN_TEMPLATE.format(self.team.name, self.job_id),
                                         {self.type: user.name})
        try:
            if result[self.type]['username'] == user.name:
                self.logger.info("handle_api: join success, adding job: %s", self.job_id)
                self.send_email()
        except KeyError:
            self.logger.exception("handle_api: bad result: %s", result)

        self.logger.info("handle_api: %s", 'end')


class AmaraReviewJob(AmaraJob):
    """Class for encapsulating new review jobs on Amara.org"""

    def __init__(self, team, job_id, time, url):
        self.type = 'approver'
        self.team = team
        self.job_id = job_id
        self.url = url
        self.duration = time
        self.logger = logging.getLogger("amara-handler.{}.AmaraReviewJob".format(__name__))

    def __repr__(self):
        str = "<AmaraReviewJob: Team: {}, job_id: {}, URL: {},duration: {}>\n"
        return str.format(self.team, self.job_id, self.url, self.duration)

    async def handle_api(self, session):
        await super().handle_api(session)

    async def handle(self, session):
        await super().handle(session)


class AmaraTranscriptionJob(AmaraJob):
    """Class for encapsulating new transcription jobs on Amara.org"""

    def __init__(self, team, job_id, time, url):
        self.type = 'subtitler'
        self.team = team
        self.job_id = job_id
        self.url = url
        self.duration = time
        self.logger = logging.getLogger("amara-handler.{}.AmaraTranscriptionJob".format(__name__))

    def __repr__(self):
        str = "<AmaraTranscriptionJob: Team: {}, job_id: {}, URL: {}, duration: {}>\n"
        return str.format(self.team, self.job_id, self.url, self.duration)

    async def handle_api(self, session):
        await super().handle_api(session)

    async def handle(self, session):
        await super().handle(session)


class AmaraAPI(object):
    """Class for encapsulating Amara.org API"""

    API_URL        = BASE_URL + "/api"
    API_TEAMS_URL  = API_URL + "/teams/"
    API_USERS_URL  = API_URL + "/users/"
    API_VIDEOS_URL = API_URL + "/videos/"

    API_TEAM_JOB_URL_TEMPLATE = API_TEAMS_URL + "{}/subtitle-requests/"
    API_USER_ACT_URL_TEMPLATE = API_USERS_URL + "{}/activity/"
    API_VIDEOS_TEMPLATE       = API_VIDEOS_URL + "{}/"
    API_JOIN_TEMPLATE         = API_TEAM_JOB_URL_TEMPLATE + "{}/"

    def __init__(self, session, api_key, name):
        self.logger = logging.getLogger("amara-handler.{}.AmaraAPI".format(__name__))
        self.api_headers = {'X-api-key'      : api_key,
                            'X-api-username' : name}
        self.__session = session
        self.teams_list = []
        self.available_jobs = []
        self.logger.info("__init__: %s", 'end')

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


class AmaraUser(object):
    """Class for encapsulating Amara.org login"""

    DEBUG = False
    LOCAL = False

    LOGIN_URL      = BASE_URL + "/en/auth/login/?next=/"
    POST_LOGIN_URL = BASE_URL + "/en/auth/login_post/"
    DASHBOARD_URL  = BASE_URL + "/en/profiles/dashboard/"

    __instance = None
    __session  = None

    def __init__(self):
        self.logger = logging.getLogger("amara-handler.{}.AmaraUser".format(__name__))
        self.logger.info("__init__: %s", 'end')

    @staticmethod
    def get_db_user():
        module_logger.info("AmaraUser.__get_db_user: %s", 'start')
        login = {}
        login['user'] = os.getenv('USER', "")
        login['pass'] = os.getenv('PASS', "")
        login['api_key'] = os.getenv('API_KEY', "")
        module_logger.info("AmaraUser.__get_db_user: %s", 'end')
        return login

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
            cls.__instance.teams = []
        return cls.__instance

    async def auth_session(self):
        self.logger.info("auth_session: %s", 'start')

        async with self.__session.get(self.LOGIN_URL) as response:
            await response.read()
            csrf = response.cookies.get('csrftoken').value
            self.logger.debug("Found CSRF: %s", csrf)
        self.auth = {
            'csrfmiddlewaretoken' : csrf,
            'username' : self.name,
            'password' : self.password,
        }
        ref = {'referer' : self.LOGIN_URL}
        async with self.__session.post(self.POST_LOGIN_URL, data=self.auth, headers=ref) as response:
            if response.status != 200:
                self.logger.error("error while joining: %s, status: %s, headers: %s",
                    self.POST_LOGIN_URL, response.status, response.headers)
                raise

            await response.read()
            if self.DEBUG:
                for cookie in self.__session.cookie_jar:
                    self.logger.debug("Found cookie: %s", cookie)
                # self.auth['sessionid'] = response.cookies.get('sessionid').value

            self.logger.info("auth_session: %s", 'end')
            return response

    def fetch_all_teams_scrape(self, doc):
        self.logger.info("fetch_teams: %s", 'start')

        self.teams = []
        root = html.fromstring(doc)
        menu = root.get_element_by_id('user-menu')
        if menu is not None:
            ul = menu.getnext()
            for candidate in ul.findall('.//a'):
                href = candidate.attrib['href']
                if not href.startswith('/en/teams/'):
                    continue

                name = href.split('/')[-2]

                if name == 'my':  # Ignore the paged teams listings link.
                    continue

                self.teams.append(AmaraTeam(name))
        self.logger.debug("fetch_teams: Found: %i teams", len(self.teams))
        self.logger.info("fetch_teams: %s", 'end')

    @classmethod
    async def init(cls, session):
        module_logger.info("AmaraUser.init: %s", 'start')

        debug = os.getenv('DEBUG', "FALSE")
        if debug.upper() == "FALSE":
            cls.DEBUG = False
            module_logger.info("DEBUG is false")
        else:
            module_logger.info("DEBUG is true")
            cls.DEBUG = True

        local = os.getenv('LOCAL', "FALSE")
        if local.upper() == "FALSE":
            cls.LOCAL = False
            module_logger.info("LOCAL is false")
        else:
            cls.LOCAL = True
            module_logger.info("LOCAL is true")


        # I know this is weird but __new__ has to be called first
        user = AmaraUser()
        user.__session = session

        response = await user.auth_session()
        doc = await response.text()
        user.fetch_all_teams_scrape(doc)

        user.teams_by_name = {}
        user.teams_by_number = {}
        for team in user.teams:
            user.teams_by_name[team.name] = team
            slug = AmaraTeam.get_slug(team.name)
            if slug not in user.teams_by_number:
                user.teams_by_number[slug] = [team]
            else:
                user.teams_by_number[slug].append(team)

        await user.fetch_current_jobs()
        module_logger.info("AmaraUser.init: %s", 'end')

    async def fetch_dashboard_html(self):
        self.logger.info("fetch_dashboard_html: %s", 'start')

        response = await self.__session.get(self.DASHBOARD_URL)
        doc = await response.text()
        root = html.fromstring(doc)

        self.logger.info("fetch_dashboard_html: %s", 'end')
        return root

    async def fetch_current_jobs(self):
        self.logger.info("fetch_current_jobs: %s", 'start')

        def team_from_html(node):
            # node is of form: <li><a href='...'></a>
            href = curr_job[0].attrib['href']
            # matching /en/teams/ondemand212/ to get group name
            team_name = re.search(r"/([-\w]+)/$", href).group(1)
            return self.teams_by_name[team_name]

        self.current_jobs = []
        root = await self.fetch_dashboard_html()

        divs = root.findall(".//div[@class='section']")
        # divs[0] is the first div, divs[0][0] is the child of the div
        # <div><h3>Available assignments</h3>
        if len(divs) > 1 and "assignments" in divs[0][0].text:
            # divs[0][1] is the second child of the div
            # <div><h3></h3><ul>
            li = divs[0][1].findall(".//li")  # find all the current jobs
            for curr_job in li:
                team = team_from_html(curr_job)
                self.current_jobs.append(team.name)

        self.logger.info("fetch_current_jobs: Found jobs: \n\t%s",
            "\n\t".join(map(str, self.current_jobs)))
        self.logger.info("fetch_current_jobs: %s", 'end')

    def save_page(self, team_name, doc):
        DB = boto3.resource("dynamodb", region_name=AWS_REGION)
        table = DB.Table('stored_pages')
        id = str(datetime.utcnow()) + "::" + team_name
        response = table.put_item(
           Item={
                'ID': id,
                'page': doc,
            }
        )

    async def find_all_team_jobs(self, team_name, link):
        self.logger.info("find_all_team_jobs: %s", 'start')

        self.available_jobs = []
        team = self.teams_by_name[team_name]
        self.logger.debug("find_all_team_jobs: found team: %s", team_name)

        root = None
        if self.LOCAL and self.DEBUG:
            self.logger.info("find_all_team_jobs: %s", 'adding debug assignments')
            tree = None
            if team.name == 'ondemand808':
                tree = html.parse("debug/808-handle-two-transcription-jobs.htm")
            elif team.name == 'ondemand616':
                tree = html.parse("debug/616-handle-one-transcription-job.htm")
            elif team.name == 'ondemand212':
                tree = html.parse("debug/212-handle-one-review-job.htm")
            elif team.name == 'ondemand868-captioning':
                tree = html.parse("debug/427-handle-4-transcription-jobs.htm")
            root = tree.getroot()
        else:
            self.logger.info("find_all_team_jobs: fetching assignment for team: %s", team.name)
            response = await self.__session.get(link)
            doc = await response.text()
            if response.status != 200:
                self.logger.error("error while joining: %s, status: %s, headers: %s, text: %s",
                    link, response.status, response.headers, doc)
                return
            else:
                root = html.fromstring(doc)
                if self.DEBUG:
                    self.save_page(team_name, doc)

        jobs = root.xpath("//div[@class='videoCard']")
        self.logger.debug("find_all_team_jobs: found %i jobs", len(jobs))

        for job in jobs:
            xpath_str = ".//span[@class='videoCard-duration']"
            time_span = job.xpath(xpath_str)
            time = 0
            if not len(time_span) > 0:
                self.logger.error("find_all_team_jobs: failed to find time for job: %s", job)
            else:
                time_str = time_span[0].text
                m, s = time_str.split(':')
                time = int(s) + int(m)*60

            xpath_str = ".//a[@class='button cta']"
            a = job.xpath(xpath_str)
            if not len(a) > 0:
                self.logger.error("find_all_team_jobs: xpath: %s failed to find link", xpath_str)
                return

            url = a[0].attrib['href']
            match = re.search(r"/en/videos/([\w\d]+).*/(\w+)/$", url)
            id = match.group(1)
            type = match.group(2)
            self.logger.debug("find_all_team_jobs: found job id: %s, time: %i, type: %s, url: %s", id, time, type, url)

            job_obj = None
            if type == 'subtitler':
                job_obj = AmaraTranscriptionJob(team, id, time, url)
            elif type == 'approver':
                job_obj = AmaraReviewJob(team, id, time, url)
            else:
                self.logger.error("find_all_team_jobs: bad type: %s", type)
                return

            job_obj.referer = link
            self.available_jobs.append(job_obj)

        self.logger.info("find_all_team_jobs: %s", 'end')

    async def signup_for_job(self, team_name, link):
        self.logger.info("signup_for_job: team: %s, start", team_name)

        if team_name in self.current_jobs:
            self.logger.info("signup_for_job: already have job for team: %s, end", team_name)
            return

        await self.find_all_team_jobs(team_name, link)
        if self.available_jobs:
            self.logger.info("signup_for_job: found %i available jobs", len(self.available_jobs))
            job = sorted(self.available_jobs).pop()
            await job.handle(self.__session)

        self.logger.info("signup_for_job: team: %s, end", team_name)
