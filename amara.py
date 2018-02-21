import boto3
import re
import os
from SESEmail import SESEmail
from datetime import timedelta, datetime
from bs4 import BeautifulSoup
from aiohttp import ClientSession, TCPConnector

DB = boto3.resource("dynamodb")
BASE_URL = "https://amara.org"


class AmaraTask(object):
    """Class for encapsulating Tasks on Amara.org"""

    # jason.e.stewart gmail account
    # WEBHOOKS_URL = "https://hooks.zapier.com/hooks/catch/738949/z8ql5t/"
    # jason baynvc account
    WEBHOOKS_URL = "https://hooks.zapier.com/hooks/catch/2976959/zwt88b/"

    DEBUG = False

    EN_URL = "/en/videos/"
    VIDEO_URL_TEMPLATE = BASE_URL + EN_URL + "{}/en/?team={}"
    VIDEO_URL_REGEX = re.compile(r"^\w+")

    ALERT_REVIEW_TERMS = []  # What terms should trigger a review alert
    ALERT_REVIEW_STRING = ""
    ALERT_REVIEW_REGEX = None

    ALERT_NEW_TERMS = []  # What terms should trigger a new video alert
    ALERT_NEW_STRING = ""
    ALERT_NEW_REGEX = None

    def __init__(self, team, url='', time='', text='', video_url='', delta=None):
        self.team = team
        self.url = url
        self.video_url = video_url
        self.delta = delta
        self.time = time
        self.text = text
        self.type = ''
        self.film_id = ''

    def __repr__(self):
        return "<AmaraTask: {}>\n".format(self)

    def __str__(self):
        return "Team: {}\tURL: {}\n\tType: {}\n\tFilm ID: {}\t\nVideo URL: {}\n\tdelta: {}\n\ttime: {}\n\ttext: {}\n".format(
            self.team, self.url, self.type, self.film_id, self.video_url, self.delta, self.time, self.text)

    @staticmethod
    def map_time_component(time_str):
        component_mapping = {
            'year': timedelta(weeks=52.25),
            'month': timedelta(weeks=4.34524),
            'week': timedelta(weeks=1),
            'day': timedelta(days=1),
            'hour': timedelta(hours=1),
            'minute': timedelta(minutes=1)
        }
        return component_mapping[time_str]

    @staticmethod
    def time_str_to_delta(time_str):
        """comp_to_delta('5 hours') returns datetime.timedelta(18000),"""
        time_str = time_str.replace('ago', '').strip().rstrip('s')
        numerator, comp = time_str.split(' ')
        return int(numerator) * AmaraTask.map_time_component(comp)

    def set_delta(self):
        """ Parses e.g. 1 day, 5 hours ago as time delta"""
        times = self.time.split(',')
        self.delta = -sum([AmaraTask.time_str_to_delta(c) for c in times], timedelta())

    def set_video_url(self, url):
        url = url.strip(self.EN_URL)
        self.film_id = self.VIDEO_URL_REGEX.match(url).group()
        self.video_url = self.VIDEO_URL_TEMPLATE.format(self.film_id, self.team.name)

    @classmethod
    def init_tasks(cls):
        if cls.DEBUG:
            # cls.WEBHOOKS_URL = os.getenv('URL', cls.WEBHOOKS_URL)
            # print("found webhooks url: {}".format(cls.WEBHOOKS_URL))
            pass

        cls.init_new()
        cls.init_review()

    @classmethod
    def init_new(cls):
        cls.ALERT_NEW_TERMS = ['added a video', 'unassigned']
        cls.ALERT_NEW_STRING = "|".join(cls.ALERT_NEW_TERMS)
        if cls.DEBUG:
            cls.ALERT_NEW_STRING = os.getenv("ALERT_NEW",
                                             cls.ALERT_NEW_STRING)
            print("found new regex: {}".format(cls.ALERT_NEW_STRING))

        cls.ALERT_NEW_REGEX = re.compile(cls.ALERT_NEW_STRING)

    @classmethod
    def init_review(cls):
        cls.ALERT_REVIEW_TERMS = [r"endorsed.*(transcriber)"]
        cls.ALERT_REVIEW_STRING = "|".join(cls.ALERT_REVIEW_TERMS)
        if cls.DEBUG:
            cls.ALERT_REVIEW_STRING = os.getenv("ALERT_REVIEW",
                                                cls.ALERT_REVIEW_STRING)
            print("found review regex: {}".format(cls.ALERT_REVIEW_STRING))

        cls.ALERT_REVIEW_REGEX = re.compile(cls.ALERT_REVIEW_STRING)

    def filter(self):
        job = None
        if self.ALERT_NEW_REGEX.search(self.text):
            job = AmaraTranscriptionJob(self)
        elif self.ALERT_REVIEW_REGEX.search(self.text):
            job = AmaraReviewJob(self)
        return job


class AmaraTeam(object):
    """Class for encapsulating Teams on Amara.org"""

    TEAM_URL_TEMPLATE = BASE_URL + "/en/teams/{}/activity/"

    def __init__(self, name, url):
        self.name = name
        self.url = url

    def make_url(self):
        return self.TEAM_URL_TEMPLATE.format(self.name)

    def __repr__(self):
        return "<AmaraTeam: {}>\n".format(self)

    def __str__(self):
        return "Name: {}\tURL: {}\n".format(self.name, self.url)


class AmaraJob(object):
    """Class for encapsulating new jobs on Amara.org"""

    DEBUG = False

    EDITOR_URL = "/en/subtitles/editor/"
    JOB_URL_TEMPLATE = BASE_URL + EDITOR_URL + "{}/en/?team={}"

    def __repr__(self):
        return "<AmaraJob: {}>\n".format(self)

    def __str__(self):
        return "Task: {}\n".format(self.task)

    @classmethod
    async def handle_jobs(cls, session, jobs):
        user = AmaraUser()
        curr_job_teams = await user.fetch_current_jobs(session)

        avail_jobs = list(filter(lambda j: j and j.task.team.name not in curr_job_teams, jobs))

        for job in avail_jobs:
            url = cls.JOB_URL_TEMPLATE.format(job.task.film_id, job.task.team.name)
            print("Found new job: {}, URL: {}".format(job, url))
            await job.handle(session)

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

    async def send_email(self, session):
        await self.save_page(session)
        task = self.task

        email = SESEmail()
        email.subject = "Amara alert, type: {}, team: {}".format(self.type, task.team.name)
        email.body = """<html>
<head></head>
<body>
  <h1>Amara Alert: {type}</h1>
  <p>Action from team {team} requires your attention
    <a href='{team_url}'>{team_url}</a></p>
  <p><a href='{url}'>{url}</a>.</p>
</body>
</html>
        """.format(team=task.team.name,
                   type=self.type,
                   team_url=task.team.url,
                   url=task.video_url)
        email.send_email()


class AmaraReviewJob(AmaraJob):
    """Class for encapsulating new review jobs on Amara.org"""

    NO_REVIEW_TEAMS = ['ondemand060', 'ondemand616', 'ondemand427-english-team',
                       'ondemand750', 'ondemand806', 'ondemand828', 'ondemand830', 'ondemand676']

    def __init__(self, task):
        self.type = 'review'
        self.task = task

    async def handle(self, session):
        if self.task.team.name not in self.NO_REVIEW_TEAMS:
            await self.send_email(session)


class AmaraTranscriptionJob(AmaraJob):
    """Class for encapsulating new transcription jobs on Amara.org"""

    JOIN_URL_TEMPLATE = "/en/videos/{}/collaborations/en/join/subtitler/"

    def __init__(self, task):
        self.type = 'transcription'
        self.task = task

    async def handle(self, session):
        doc = ''
        if self.DEBUG:
            self.task.film_id = "A3B5wmBhxbPr"
            with open("transcription-test.html") as f:
                doc = f.read()
                print("DEBUG: found doc length: {}".format(len(doc)))
        else:
            response = await session.post(self.task.video_url)
            doc = await response.text()

        soup = BeautifulSoup(doc, 'html.parser')
        prog_node = soup.find('section', 'videoSubtitles-progress')
        if 'English subtitles' in prog_node.get_text():
            href = soup.find('a', 'button cta block')['href']
            if 'join' not in href:
                print("expected 'join' but found: {}".format(href))
            else:
                join_url = self.JOIN_URL_TEMPLATE.format(self.task.film_id)
                if not href == join_url:
                    print("looking for join URL: {}, and found: {}\n".format(join_url, href))
                async with session.post(BASE_URL + join_url) as response:
                    if response.status is not '200':
                        print("error while joining: {}, status: {}\nheaders: {}".format(join_url, response.status, response.headers))
                        await self.send_email(session)
                    else:
                        user = AmaraUser()
                        user.add_new_job(self)
                        await self.send_email(session)


class AmaraUser(object):
    """Class for encapsulating Amara.org login"""

    DEBUG = False

    LOGIN_URL = "https://amara.org/en/auth/login/?next=/"
    POST_LOGIN_URL = "https://amara.org/en/auth/login_post/"
    DASHBOARD_URL = "https://amara.org/en/profiles/dashboard/"

    __instance = None

    def __init__(self):
        self.__current_jobs = None

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = object.__new__(cls)
            login = cls.__get_db_user()
            cls.__instance.name = login['user']
            cls.__instance.password = login['pass']
        return cls.__instance

    @staticmethod
    def __get_db_user():
        user = DB.Table("user")
        response = user.get_item(Key={"service_name" : "amara"})
        return response["Item"]

    def add_new_job(self, job):
        if self.__current_jobs is None:
            print("add_new_job called before current jobs set")
        else:
            self.__current_jobs.append(job)

    async def fetch_current_jobs(self, session):
        if self.__current_jobs is None:

            async with ClientSession(connector=TCPConnector(verify_ssl=False)) as session:

                response = await session.get(self.DASHBOARD_URL)
                doc = await response.text()

                soup = BeautifulSoup(doc, 'html.parser')
                menu = soup.find(id='page-header')

                self.__current_jobs = []
                if self.DEBUG:
                    task = AmaraTask(AmaraTeam("ondemand060", "/en/teams/ondemand060/"))
                    task.set_video_url('/en/videos/8wxNgiJyLY0H/info/wwwyoutubecomwatchvgi1al50hxg8/?team=ondemand060')
                    task.film_id = "8wxNgiJyLY0H"
                    task.type = 'new'
                    self.__current_jobs.append(task)
                    task = AmaraTask(AmaraTeam("ondemand616", "/en/teams/ondemand616/"))
                    task.set_video_url('/en/videos/8wxNgiJyLY0H/info/wwwyoutubecomwatchvgi1al50hxg8/?team=ondemand060')
                    task.film_id = "8wxNgiJyLY0H"
                    task.type = 'new'
                    self.__current_jobs.append(task)

        return self.__current_jobs
