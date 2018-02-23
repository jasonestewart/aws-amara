import boto3
import re
from SESEmail import SESEmail
from datetime import datetime
from lxml import html
import logging
# from IPython import embed

AWS_REGION = "us-east-1"
DB = boto3.resource("dynamodb", region_name=AWS_REGION)
BASE_URL = "https://amara.org"

module_logger = logging.getLogger('amara-handler.{}'.format(__name__))

class AmaraTask(object):
    """Class for encapsulating Tasks on Amara.org"""

    EN_URL = "/en/videos/"
    VIDEO_URL_TEMPLATE = BASE_URL + EN_URL + "{}/en/?team={}"
    VIDEO_URL_REGEX = re.compile(r"^\w+")

    def set_video_url(self, url):
        url = url.strip(self.EN_URL)
        self.film_id = self.VIDEO_URL_REGEX.match(url).group()
        self.video_url = self.VIDEO_URL_TEMPLATE.format(self.film_id, self.team.name)


class AmaraTeam(object):
    """Class for encapsulating Teams on Amara.org"""

    TEAM_URL_TEMPLATE = BASE_URL + "/en/teams/{}/"

    def __init__(self, name, url=''):
        self.name = name
        self.url = self.TEAM_URL_TEMPLATE.format(name)

    def __repr__(self):
        return "<AmaraTeam: Name: {}, URL: {}>".format(self.name, self.url)


class AmaraJob(object):
    """Class for encapsulating new jobs on Amara.org"""

    LOCAL = False
    DEBUG = False
    AUTO_JOIN_JOBS = False

    EDITOR_URL = "/en/subtitles/editor/"
    JOB_URL_TEMPLATE = BASE_URL + EDITOR_URL + "{}/en/?team={}"

    def __init__(self):
        self.logger = logging.getLogger("amara-handler.{}.AmaraJob".format(__name__))

    async def save_page(self, session):
        async with session.get(self.task.video_url) as response:
            doc = await response.text()

            table = DB.Table('stored_pages')
            id = str(datetime.utcnow()) + self.task.team.name
            response = table.put_item(
               Item={
                    'ID': id,
                    'page': doc,
                    'url': self.task.video_url,
                }
            )

    def send_email(self):
        # await self.save_page(session)
        team = self.team

        email = SESEmail()
        email.subject = "Amara alert, type: {}, team: {}".format(self.type, team.name)
        email.body = """<html>
<head></head>
<body>
  <h1>Amara Alert: {type}</h1>
  <p>Action from team {team} requires your attention
    <a href='{team_url}'>{team_url}</a></p>
    <p><a href='{url}'>{url}</a></p>
</body>
</html>
        """.format(team=team.name,
                   type=self.type,
                   url=self.url,
                   team_url=team.url)
        email.send_email()

    async def handle(self, session):
        root = None
        if self.DEBUG and self.LOCAL:
            if self.team.name is 'ondemand808':
                root = html.parse("debug/808-handle-two-transcription-jobs.htm")
            elif self.team.name is 'ondemand616':
                root = html.parse("debug/transcribe-job.htm")
            elif self.team.name is 'ondemand212':
                root = html.parse("debug/212-handle-one-review-job.htm")
            elif self.team.name is 'ondemand427-english-team':
                root = html.parse("debug/427-handle-4-transcription-jobs.htm")
        else:
            response = await session.post(self.url)
            doc = await response.text()
            root = html.fromstring(doc)

        a = root.findall(".//a[@class='button cta']")
        if len(a) > 0:
            href = a[0].attrib['href']
            if href.startswith('http'):
                url = href
            else:
                url = BASE_URL + href
            self.send_email()

            if self.DEBUG and self.LOCAL:
                return

            async with session.post(url) as response:
                if response.status is not '200':
                    self.logger.error("error while joining: {}, status: {}\nheaders: {}".format(url, response.status, response.headers))
                else:
                    user = AmaraUser()
                    user.add_new_job(self)


class AmaraReviewJob(AmaraJob):
    """Class for encapsulating new review jobs on Amara.org"""

    NO_REVIEW_TEAMS = ['ondemand060', 'ondemand616', 'ondemand427-english-team',
                       'ondemand750', 'ondemand806', 'ondemand828', 'ondemand830', 'ondemand676']

    REVIEW_ASS_TEMPLATE = "/en/teams/{}/assignments/?type=review&language=en"

    def __init__(self, team):
        self.type = 'review'
        self.team = team
        self.logger = logging.getLogger("amara-handler.{}.AmaraReviewJob".format(__name__))
        self.url = BASE_URL + self.REVIEW_ASS_TEMPLATE.format(team.name)

    def __repr__(self):
        return "<AmaraReviewJob: Team: {}, URL: {}>\n".format(self.team, self.url)


class AmaraTranscriptionJob(AmaraJob):
    """Class for encapsulating new transcription jobs on Amara.org"""

    JOIN_URL_TEMPLATE = "/en/videos/{}/collaborations/en/join/subtitler/"

    TRANSCRIBE_ASS_TEMPLATE = "/en/teams/{}/assignments/?type=transcribe&language=en"

    def __init__(self, team):
        self.type = 'transcription'
        self.team = team
        self.logger = logging.getLogger("amara-handler.{}.AmaraTranscriptionJob".format(__name__))
        self.url = BASE_URL + self.TRANSCRIBE_ASS_TEMPLATE.format(team.name)

    def __repr__(self):
        return "<AmaraTranscriptionJob: Team: {}, URL: {}>\n".format(self.team, self.url)


class AmaraUser(object):
    """Class for encapsulating Amara.org login"""

    LOCAL = False
    DEBUG = False

    LOGIN_URL      = BASE_URL + "/en/auth/login/?next=/"
    POST_LOGIN_URL = BASE_URL + "/en/auth/login_post/"
    DASHBOARD_URL  = BASE_URL + "/en/profiles/dashboard/"

    __instance = None
    __session  = None

    @staticmethod
    def debug_teams():
        return {'ondemand808': AmaraTeam('ondemand808'),
                'ondemand043': AmaraTeam('ondemand043'),
                'ondemand616': AmaraTeam('ondemand616'),
                'ondemand212': AmaraTeam('ondemand212'),
                'ondemand427-english-team': AmaraTeam('ondemand427-english-team'),
        }

    def __init__(self):
        self.logger = logging.getLogger("amara-handler.{}.AmaraUser".format(__name__))
        self.logger.debug("AmaraUser: __init__()")

    def __new__(cls):
        module_logger.info("AmaraUser: __new__()\n")
        if cls.__instance is None:
            cls.__instance = object.__new__(cls)
            login = cls.__get_db_user()
            cls.__instance.name = login['user']
            cls.__instance.password = login['pass']
            cls.__instance.current_jobs = None
            cls.__instance.available_jobs = None
        return cls.__instance

    async def handle_jobs(self):
        self.logger.info("handle_jobs: %s", 'start')

        def curr_job_filter(curr, new):
            cond = curr.team.name == new.team.name and curr.type == new.type
            action = 'accepting'
            if cond:
                action = 'rejecting'
            self.logger.debug("AmaraUser.job_filter: action: {}, curr_job: {}, new job: {}".format(action, curr, new))
            return cond

        self.logger.debug("AmaraUser.handle_jobs: available jobs: {}".format(self.available_jobs))

        if self.available_jobs is not None:
            for job in self.available_jobs:
                curr_jobs = self.get_current_jobs()
                matches = list(filter(lambda j: curr_job_filter(j, job), curr_jobs))
                if not matches:
                    self.logger.debug("AmaraUser.handle_jobs: Found new job: {}".format(job))
                    await job.handle(self.__session)
                else:
                    self.logger.debug("AmaraUser.handle_jobs: axed new job: {}".format(job))

    async def auth_session(self):
        async with self.__session.get(self.LOGIN_URL) as response:
            await response.read()
            crsf = response.cookies.get('csrftoken').value
        auth = {
            'csrfmiddlewaretoken' : crsf,
            'username' : self.name,
            'password' : self.password,
        }
        ref = {'referer' : self.LOGIN_URL}
        return await self.__session.post(self.POST_LOGIN_URL, data=auth, headers=ref)

    def fetch_teams(self, doc):
        teams = []
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

                teams.append(AmaraTeam(name, href))
        self.logger.debug("AmaraUser.fetch_teams: Found: {} teams".format(len(teams)))
        return teams

    @classmethod
    async def init(cls, session):
        logging.debug("AmaraUser: init()\n")

        # I know this is weird but __new__ has to be called first
        user = AmaraUser()
        user.__session = session

        response = await user.auth_session()
        doc = await response.text()
        teams = user.fetch_teams(doc)
        dict = {}
        for team in teams:
            dict[team.name] = team
        user.teams = dict
        user.current_jobs = await user.fetch_current_jobs()

    @staticmethod
    def __get_db_user():
        user = DB.Table("user")
        response = user.get_item(Key={"service_name" : "amara"})
        return response["Item"]

    def add_available_job(self, job):
        if self.available_jobs is None:
            self.available_jobs = []
        self.available_jobs.append(job)

    def add_new_job(self, job):
        if self.current_jobs is None:
            self.logger.error("AmaraUser.add_new_job called before current jobs set")
        else:
            self.current_jobs.append(job)

    def get_current_jobs(self):
        return self.current_jobs

    async def fetch_current_jobs(self):

        def team_from_html(node):
            # node is of form: <li><a href='...'></a>
            href = curr_job[0].attrib['href']
            # matching /en/teams/ondemand212/ to get group name
            team_name = re.search(r"/([-\w]+)/$", href).group(1)
            return self.teams[team_name]

        current_jobs = []
        root = None
        if self.DEBUG:
            tree = html.parse("debug/dashboard.htm")
            root = tree.getroot()
        else:
            response = await self.__session.get(self.DASHBOARD_URL)
            doc = await response.text()
            root = html.fromstring(doc)

        # embed()
        divs = root.findall(".//div[@class='section']")
        # divs[0] is the first div, divs[0][0] is the child of the div
        # <div><h3>Available assignments</h3>
        if len(divs) > 1 and "assignments" in divs[0][0].text:
            # divs[0][1] is the second child of the div
            # <div><h3></h3><ul>
            li = divs[0][1].findall(".//li")  # find all the current jobs
            for curr_job in li:
                job = None
                if b"Reviewer" in html.tostring(curr_job):
                    job = AmaraReviewJob(team_from_html(curr_job))
                elif b"Subtitler" in html.tostring(curr_job):
                    job = AmaraTranscriptionJob(team_from_html(curr_job))
                else:
                    self.logger.error("Error: AmaraUser.fetch_current_jobs: didn't find Reviewer or Subtitler{}".format(html.tostring(curr_job)))
                    return
                current_jobs.append(job)

        self.logger.debug("AmaraUser.fetch_current_jobs: Found jobs: {}".format(current_jobs))

        return current_jobs

    async def check_for_new_jobs(self, team):

        # parse the li in the collaborations box
        # the procedure is the same for both review and transcription jobs
        # only the class attribute is different
        def parse_collaboration(r, class_):
            job = False
            xpath = ".//li[@class='{}']".format(class_)
            # embed()
            e = r.find(xpath)
            if e is None:  # ERROR!!
                self.logger.error('searching for jobs, no <li class={}>, team: {}'.format(class_, team.name))
                return False

            e = e.find(".//span")

            # <span class="total">1</span> - shows how many jobs available
            if int(e.text) > 0:
                # there are jobs
                job = True
            return job

        response = await self.__session.get(team.url)
        doc = await response.text()
        root = html.fromstring(doc)

        if self.DEBUG and self.LOCAL:
            self.logger.debug("AmaraUser.check_for_new_jobs: debug for team: {}".format(team.name))
            filename = ''
            if team.name is 'ondemand808':
                filename = "debug/808-2-available-transcription-assignments.htm"
            elif team.name is 'ondemand043':
                filename = "debug/043-no-assignments.htm"
            elif team.name is 'ondemand212':
                filename = "debug/212-one-available-review-assignment.htm"
            elif team.name.startswith('ondemand427'):
                filename = "debug/427-4-available-transcription-assignments.htm"
            elif team.name is 'ondemand616':
                filename = "debug/616-one-available-transcription-assignment.htm"
            tree = html.parse(filename)
            root = tree.getroot()

        # we can only handle new-style teams
        # old-style teams have had no activity for a year and haven't been upgraded
        # their body tag will look like
        # <body class=v1 team_dashboard>
        # so we look for that and return if it exists
        body = root.find(".//body[@class='v1 team_dashboard']")
        if body is not None:  # if it exists, this is an old-style team, skip it
            self.logger.debug("skipping old style team: {}".format(team.url))
            return

        self.logger.debug("Jobs for team: {}".format(team.name))

        # when a team has available jobs there will be a div
        # <div id=available_assignments></div>
        try:
            root.get_element_by_id("available_assignments")
        except KeyError:  # if the div does not exist, there are no jobs
            self.logger.debug("\tno jobs for team: {}".format(team.name))
            return

        self.logger.debug("\tfound jobs for team: {}".format(team.name))

        # there are jobs, find out if they are review or transcription
        for type in ['transcribe', 'review']:
            class_ = 'availableCollabs-' + type
            if parse_collaboration(root, class_):
                job = None
                if type == 'transcribe':
                    job = AmaraTranscriptionJob(team)
                else:
                    job = AmaraReviewJob(team)

                self.logger.debug("\t\tfound {} for team: {}".format(type, team.name))

                self.add_available_job(job)
            self.logger.debug("\t\tno {} jobs for team: {}".format(type, team.name))
