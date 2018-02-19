import json
import re
import itertools
import boto3
from aiohttp import ClientSession, TCPConnector
import asyncio
import os
from datetime import timedelta, datetime
from bs4 import BeautifulSoup
from html.parser import HTMLParser
import cProfile
import io
import pstats

DEBUG = ""
DB = boto3.resource("dynamodb")
LOCAL = False
PROFILE = False

# time cutoff for interesting events in seconds (10 minutes)
TIME_THRESHOLD = -60 * 10


class AmaraTask(object):
    """Class for encapsulating Tasks on Amara.org"""

    # jason.e.stewart gmail account
    # WEBHOOKS_URL = "https://hooks.zapier.com/hooks/catch/738949/z8ql5t/"
    # jason baynvc account
    WEBHOOKS_URL = "https://hooks.zapier.com/hooks/catch/2976959/zwt88b/"

    BASE_URL = "https://amara.org"

    ALERT_REVIEW_TERMS = []  # What terms should trigger a review alert
    ALERT_REVIEW_STRING = ""
    ALERT_REVIEW_REGEX = None

    ALERT_NEW_TERMS = []  # What terms should trigger a new video alert
    ALERT_NEW_STRING = ""
    ALERT_NEW_REGEX = None

    NO_REVIEW_TEAMS = ['ondemand060', 'ondemand616']

    def __init__(self, team, url='', video_url='', time='', text='', delta=None):
        self.team = team
        self.url = url
        self.video_url = video_url
        self.delta = delta
        self.time = time
        self.text = text

    def __repr__(self):
        return "<AmaraTask: {}>\n".format(self)

    def __str__(self):
        return "Team: {}\n\tURL: {}\n\tVideo URL: {}\n\tdelta: {}\n\ttime: {}\n\ttext: {}\n".format(
            self.team, self.url, self.video_url, self.delta, self.time, self.text)

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

    async def handle_new(self, session):
        await self.send_webhook(session, 'new')

    async def handle_review(self, session):
        if self.team.name in self.NO_REVIEW_TEAMS:
            return
        await self.send_webhook(session, 'review')

    async def send_webhook(self, session, type):
        payload = {"team": self.team.name,
                   "url": self.url,
                   "video_url": self.BASE_URL + self.video_url,
                   "type": type}

        async with session.post(self.WEBHOOKS_URL, json=payload) as response:
            response = await response.read()
            print("sending message: {} to url:{}\n".format(payload,
                                                           self.WEBHOOKS_URL))

    @classmethod
    def init_tasks(cls):
        if DEBUG:
            cls.WEBHOOKS_URL = os.getenv('URL', cls.WEBHOOKS_URL)
            print("found webhooks url: {}".format(cls.WEBHOOKS_URL))
        cls.init_new()
        cls.init_review()

    @classmethod
    def init_new(cls):
        cls.ALERT_NEW_TERMS = ['added a video', 'unassigned']
        cls.ALERT_NEW_STRING = "|".join(cls.ALERT_NEW_TERMS)
        if DEBUG:
            cls.ALERT_NEW_STRING = os.getenv("ALERT_NEW",
                                             cls.ALERT_NEW_STRING)
            print("found new regex: {}".format(cls.ALERT_NEW_STRING))

        cls.ALERT_NEW_REGEX = re.compile(cls.ALERT_NEW_STRING)

    @classmethod
    def init_review(cls):
        cls.ALERT_REVIEW_TERMS = [r"endorsed.*(transcriber)"]
        cls.ALERT_REVIEW_STRING = "|".join(cls.ALERT_REVIEW_TERMS)
        if DEBUG:
            cls.ALERT_REVIEW_STRING = os.getenv("ALERT_REVIEW",
                                                cls.ALERT_REVIEW_STRING)
            print("found review regex: {}".format(cls.ALERT_REVIEW_STRING))

        cls.ALERT_REVIEW_REGEX = re.compile(cls.ALERT_REVIEW_STRING)

    async def filter(self, session):
        if DEBUG:
            print("filtering task: {}\n".format(self))
        if self.ALERT_NEW_REGEX.search(self.text):
            return await self.handle_new(session)
        elif self.ALERT_REVIEW_REGEX.search(self.text):
            return await self.handle_review(session)


class AmaraTeam(object):
    """Class for encapsulating Teams on Amara.org"""

    TEAM_URL_TEMPLATE = "https://amara.org/en/teams/{}/activity/"

    def __init__(self, name, url):
        self.name = name
        self.url = url

    def make_url(self):
        return self.TEAM_URL_TEMPLATE.format(self.name)

    def __repr__(self):
        return "<AmaraTeam: {}>\n".format(self)

    def __str__(self):
        return "Name: {}\tURL: {}\n".format(self.name, self.url)


class AmaraUser(object):
    """Class for encapsulating Amara.org login"""

    LOGIN_URL = "https://amara.org/en/auth/login/?next=/"
    POST_LOGIN_URL = "https://amara.org/en/auth/login_post/"

    __instance = None

    def __new__(cls):
        if cls.__instance is None:
            cls.__instance = object.__new__(cls)
            login = cls.get_user()
            cls.__instance.name = login['user']
            cls.__instance.password = login['pass']
        return cls.__instance

    @staticmethod
    def get_user():
        user = DB.Table("user")
        response = user.get_item(Key={"service_name" : "amara"})
        return response["Item"]


async def auth_session_and_fetch_teams(session):
    user = AmaraUser()

    teams = []

    if DEBUG:
        teams.append(AmaraTeam("demand-465", "/en/teams/demand-465/"))
        teams.append(AmaraTeam("ondemand060", "/en/teams/ondemand060/"))
        return teams

    async with session.get(user.LOGIN_URL) as response:
        await response.read()
        crsf = response.cookies.get('csrftoken').value

    auth = {
        'csrfmiddlewaretoken' : crsf,
        'username' : user.name,
        'password' : user.password,
    }
    ref = {'referer' : user.LOGIN_URL}

    async with session.post(user.POST_LOGIN_URL,
                            data=auth,
                            headers=ref) as response:

        doc = await response.text()

        soup = BeautifulSoup(doc, 'html.parser')
        menu = soup.find(id='user-menu')

        if menu is not None:
            for candidate in menu.find_next_sibling('ul').find_all('a'):

                if not candidate['href'].startswith('/en/teams/'):
                    continue

                name = candidate['href'].split('/')[-2]

                if name == 'my':  # Ignore the paged teams listings link.
                    continue

                teams.append(AmaraTeam(name, candidate['href']))

        return teams


class HTMLFinished(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class MyHTMLParser(HTMLParser):
    WAITING = 1
    IN_ACT_LIST = 2
    IN_TIME = 3

    def __init__(self, team):
        self.tasks = []
        self.cur_task = None
        self._state = self.WAITING
        self._seen_author = False
        self.team = team
        super().__init__()

    def handle_starttag(self, tag, attrs):
        if tag == 'p':
            return

        if self._state == self.IN_ACT_LIST:
            if tag == 'li':
                self.cur_task = AmaraTask(self.team)
            elif tag == 'span':
                self._state = self.IN_TIME
            elif tag == 'a':
                if self._seen_author:
                    attr_dict = dict(attrs)
                    self.cur_task.video_url = attr_dict['href']
                else:
                    self._seen_author = True
        elif tag == "div":
            attr_dict = dict(attrs)
            if 'id' not in attr_dict:
                return
            elif attr_dict['id'] == 'activity-list':
                self._state = self.IN_ACT_LIST

    def handle_endtag(self, tag):
        if tag == 'p':
            return

        if self._state == self.IN_ACT_LIST:
            if tag == 'ul':
                raise HTMLFinished()
        elif self._state == self.IN_TIME:
            if tag == 'span':
                self._state = self.IN_ACT_LIST
                self.cur_task.set_delta()
                if self.cur_task.delta.total_seconds() < TIME_THRESHOLD:
                    raise HTMLFinished()
                else:
                    self.tasks.append(self.cur_task)

    def handle_data(self, data):
        if self.cur_task is not None:
            self.cur_task.text += data

        if self._state == self.IN_TIME:
            self.cur_task.time += data


async def fetch_team_activities(url, team, session):
    if DEBUG:
        a = []
        time = "2 minutes ago"
        if "465" in team.name:
            team = AmaraTask(team,
                             "https://amara.org/en/teams/demand-465/activity/",
                             '/en/videos/oZSRr0kN6GE2/info/etc_layla_arabic_subs_sl_170719mp4/',
                             time,
                             "\n2 minutes ago\n\nOmnia Kamel\n  approved Arabic subtitles for ETC_Layla_Arabic_SUBS_SL_170719.mp4\n\n"
            )
            team.set_delta()
            a.append(team)
        else:
            team = AmaraTask(team,
                             "https://amara.org/en/teams/ondemand060/activity/",
                             '/en/videos/8wxNgiJyLY0H/info/wwwyoutubecomwatchvgi1al50hxg8/?team=ondemand060',
                             time,
                             "\n2 minutes ago\n\nOmnia Kamel\n  approved Arabic subtitles for ETC_Layla_Arabic_SUBS_SL_170719.mp4\n\n"
            )
            team.set_delta()
            a.append(team)

        return a

    async with session.get(url) as response:

        doc = await response.text()
        # soup = BeautifulSoup(doc, 'html.parser')
        # activity = soup.find(id='activity-list')
        p = MyHTMLParser(team)
        try:
            p.feed(doc)
        except HTMLFinished:
            pass
        return p.tasks


def update_team(table, team):
    table.put_item(
        Item={
            "team_name" : team.name,
            "team_url"  : team.url
        }
    )


def update_teams(teams):
    info = DB.Table("Info")
    response = info.get_item(Key={"key_name" : "num_teams"})
    num_teams = int(response["Item"]["key_val"])

    teams_updated = 0
    if (len(teams) > num_teams):
        db_teams_table = DB.Table("teams")
        response = db_teams_table.scan()
        db_teams = response["Items"]

        team_dict = {}
        for team in db_teams:
            team_dict[team["team_name"]] = 1

        for team in teams:
            if team["name"] not in team_dict:
                teams_updated += 1
                update_team(db_teams_table, team)

        info.update_item(
            Key={"key_name" : "num_teams"},
            UpdateExpression='SET key_val = :val1',
            ExpressionAttributeValues={':val1': len(teams)}
        )
    return teams_updated


def init_teams(teams):
    db_teams_table = DB.Table("teams")

    for team in teams:
        update_team(db_teams_table, team)

    info = DB.Table("Info")
    info.update_item(
        Key={"key_name" : "num_teams"},
        UpdateExpression='SET key_val = :val1',
        ExpressionAttributeValues={':val1': len(teams)}
    )
    return True


def init_amara_teams(event, context):
    # Create client session that will ensure we dont open new connection
    # per each request.
    teams = []
    result = ''

#     session = requests.Session()
#     teams = auth_session_and_fetch_teams(session)
#     result = init_teams(teams)

    message = "Total teams to scrape: {}\n".format(len(teams))

    body = {
        "message" : message,
        "result"  : result,
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response


async def check_amara_teams():
    async with ClientSession() as session:
        teams = await auth_session_and_fetch_teams(session)
        return teams


def get_amara_init_info():
    global DEBUG
    global LOCAL
    global PROFILE
    global TIME_THRESHOLD

    debug = os.getenv('DEBUG', "FALSE")
    if debug.upper() == "FALSE":
        DEBUG = False
        print("DEBUG is false\n")
    else:
        print("DEBUG is true\n")
        DEBUG = True

    local = os.getenv('LOCAL', "FALSE")
    if local.upper() == "FALSE":
        LOCAL = False
        print("LOCAL is false\n")
    else:
        LOCAL = True
        print("LOCAL is true\n")

    profile = os.getenv('PROFILE', "FALSE")
    if profile.upper() == "FALSE":
        PROFILE = False
        print("PROFILE is false\n")
    else:
        PROFILE = True
        print("PROFILE is true\n")

    TIME_THRESHOLD = int(os.getenv('THRESHOLD', TIME_THRESHOLD))
    print("Found THRESHOLD: {}\n".format(TIME_THRESHOLD))

    AmaraTask.init_tasks()


def check_teams(event, context):
    get_amara_init_info()

    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(check_amara_teams())
    teams = loop.run_until_complete(future)

    result = update_teams(teams)

    message = "Total teams to scrape: {}\n".format(len(teams))
    body = {
        "message" : message,
        "result"  : result,
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response


async def bound_fetch(sem, url, team, session):
    async with sem:
        return await fetch_team_activities(url, team, session)


async def run_task_checks():
    tasks = []
    sem = asyncio.Semaphore(200)

    # Create client session that will ensure we dont open new connection
    # per each request.
    async with ClientSession(connector=TCPConnector(verify_ssl=False)) as session:

        teams = await auth_session_and_fetch_teams(session)

        print("Total teams to scrape: {}\n".format(len(teams)))

        for team in teams:
            url = team.make_url()
            task = asyncio.ensure_future(bound_fetch(sem, url, team, session))
            tasks.append(task)

        # Gather all futures
        tasks = asyncio.gather(*tasks)

        # Flatten nested activities
        tasks = list(itertools.chain(*await tasks))

        print("tasks: {}\n".format(tasks))

        # Filter by terms
        for task in tasks:
            await task.filter(session)


def hello(event, context):
    get_amara_init_info()

    if LOCAL:
        print(datetime.now())

    if PROFILE:
        pr = cProfile.Profile()
        pr.enable()

    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(run_task_checks())
    loop.run_until_complete(future)

    if PROFILE:
        pr.disable()
        s = io.StringIO()
        sortby = 'cumulative'
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats()
        print(s.getvalue())

    if LOCAL:
        print(datetime.now())

    response = {
        "statusCode": 200,
        "body": "complete"
    }
    return response
