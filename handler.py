import json
import re
import itertools
import boto3
from aiohttp import ClientSession, TCPConnector
import asyncio
import os
from datetime import timedelta, datetime
from bs4 import BeautifulSoup

activity_url_template = "https://amara.org/en/teams/{}/activity/"
DEBUG = True
LOGIN_URL = "https://amara.org/en/auth/login/?next=/"
POST_LOGIN_URL = "https://amara.org/en/auth/login_post/"
DB = boto3.resource("dynamodb")

component_mapping = {
    'year': timedelta(weeks=52.25),
    'month': timedelta(weeks=4.34524),
    'week': timedelta(weeks=1),
    'day': timedelta(days=1),
    'hour': timedelta(hours=1),
    'minute': timedelta(minutes=1)
}

# time cutoff for interesting events in seconds (10 minutes)
TIME_THRESHOLD = -60 * 10


class AmaraTask:
    """Class for encapsulating Tasks on Amara.org"""

    WEBHOOKS_URL = "https://hooks.zapier.com/hooks/catch/738949/z8ql5t/"

    ALERT_REVIEW_TERMS = []  # What terms should trigger a review alert
    ALERT_REVIEW_STRING = ""
    ALERT_REVIEW_REGEX = None

    ALERT_NEW_TERMS = []  # What terms should trigger a new video alert
    ALERT_NEW_STRING = ""
    ALERT_NEW_REGEX = None

    NO_REVIEW_TEAMS = ['demand060', 'ondemand616']

    def __init__(self, team, url, delta, time, text):
        self.team = team
        self.url = url
        self.delta = delta
        self.time = time
        self.text = text

    def __repr__(self):
        return "<AmaraTask: {}>\n".format(self)

    def __str__(self):
        return "Team: {}\n\tURL: {}\n\tdelta: {}\n\ttime: {}\n\ttext: {}\n".format(
            self.team, self.url, self.delta, self.time, self.text)
            

    async def handle_new(self, session):
        await self.send_webhook(session, 'new')

    async def handle_review(self, session):
        if self.team.name in AmaraTask.NO_REVIEW_TEAMS:
            return
        await self.send_webhook(session, 'review')

    async def send_webhook(self, session, type):
        payload = {"team": self.team.name, "url": self.url, "type": type}

        async with session.post(AmaraTask.WEBHOOKS_URL, json=payload) as response:
            response = await response.read()
            print("sending message: {} to url:{}\n".format(payload,
                                                           AmaraTask.WEBHOOKS_URL))

    def init_tasks():
        if DEBUG:
            AmaraTask.WEBHOOKS_URL = os.getenv('URL', AmaraTask.WEBHOOKS_URL)
            print("found webhooks url: {}".format(AmaraTask.WEBHOOKS_URL))
        AmaraTask.init_new()
        AmaraTask.init_review()

    def init_new():
        AmaraTask.ALERT_NEW_TERMS = ['added a video', 'unassigned']
        AmaraTask.ALERT_NEW_STRING = "|".join(AmaraTask.ALERT_NEW_TERMS)
        if DEBUG:
            AmaraTask.ALERT_NEW_STRING = os.getenv("ALERT_NEW",
                                                   AmaraTask.ALERT_NEW_STRING)
            print("found new regex: {}".format(AmaraTask.ALERT_NEW_STRING))

        AmaraTask.ALERT_NEW_REGEX = re.compile(AmaraTask.ALERT_NEW_STRING)

    def init_review():
        AmaraTask.ALERT_REVIEW_TERMS = [r"endorsed.*(transcriber)"]
        AmaraTask.ALERT_REVIEW_STRING = "|".join(AmaraTask.ALERT_REVIEW_TERMS)
        if DEBUG:
            AmaraTask.ALERT_REVIEW_STRING = os.getenv("ALERT_REVIEW",
                                                      AmaraTask.ALERT_REVIEW_STRING)
            print("found review regex: {}".format(AmaraTask.ALERT_REVIEW_STRING))

        AmaraTask.ALERT_REVIEW_REGEX = re.compile(AmaraTask.ALERT_REVIEW_STRING)

    async def filter(self, session):
        if DEBUG:
            print("filtering task: {}\n".format(self))
        if AmaraTask.ALERT_NEW_REGEX.search(self.text):
            return await self.handle_new(session)
        elif AmaraTask.ALERT_REVIEW_REGEX.search(self.text):
            return await self.handle_review(session)


class AmaraTeam:
    """Class for encapsulating Tasks on Amara.org"""

    def __init__(self, name, url):
        self.name = name
        self.url = url

    def __repr__(self):
        return "<AmaraTeam: {}>\n".format(self)

    def __str__(self):
        return "Name: {}\n\tURL: {}\n".format(self.name, self.url)


def get_user():
    user = DB.Table("user")
    response = user.get_item(Key={"service_name" : "amara"})
    return response["Item"]


def timestring_to_minutes_delta(string):
    """ Parses e.g. 1 day, 5 hours ago as time delta"""

    def comp_to_delta(str_):
        """comp_to_delta('5 hours') returns datetime.timedelta(18000),"""
        str_ = str_.replace('ago', '').strip().rstrip('s')
        numerator, comp = str_.split(' ')
        return int(numerator) * component_mapping[comp]

    delta = -sum([comp_to_delta(c) for c in string.split(',')], timedelta())
    return delta


async def auth_session_and_fetch_teams(session):
    login = get_user()
    username = login['user']
    password = login['pass']

    teams = []
    
    if DEBUG:
        teams.append(AmaraTeam("demand-465","/en/teams/demand-465/"))
        teams.append(AmaraTeam("demand060","/en/teams/demand060/"))
        return teams

    async with session.get(LOGIN_URL) as response:
        await response.read()
        crsf = response.cookies.get('csrftoken').value

    auth = {
        'csrfmiddlewaretoken' : crsf,
        'username' : username,
        'password' : password,
    }
    ref = {'referer' : LOGIN_URL}

    async with session.post(POST_LOGIN_URL,
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


async def fetch_team_activities(url, team, session):

    async with session.get(url) as response:

        doc = await response.text()
        soup = BeautifulSoup(doc, 'html.parser')
        activity = soup.find(id='activity-list')

        a = []
        
        if DEBUG:
            time = "2 minutes ago"
            if "465" in team.name:
                a.append(AmaraTask(team, 
                                   "https://amara.org/en/teams/demand-465/activity/",
                                   timestring_to_minutes_delta(time),
                                   time, 
                                   "\n52 minutes ago\n\nOmnia Kamel\n  approved Arabic subtitles for ETC_Layla_Arabic_SUBS_SL_170719.mp4\n\n"
                                   )
                        )
            else:
                 a.append(AmaraTask(team, 
                                   "https://amara.org/en/teams/demand060/activity/",
                                   timestring_to_minutes_delta(time),
                                   time, 
                                   "\n52 minutes ago\n\nOmnia Kamel\n  approved Arabic subtitles for ETC_Layla_Arabic_SUBS_SL_170719.mp4\n\n"
                                   )
                          )
             

        if activity is not None:
            for item, time in [(x, x.find(class_='timestamp').text) for x in activity.find_all('li')]:

                _delta = timestring_to_minutes_delta(time)

                # don't bother with tasks older than 20 minutes
                if _delta.total_seconds() < TIME_THRESHOLD:
                    break

                a.append(AmaraTask(team, url, _delta, time, item.text))

        return a


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
        if DEBUG:
            payload = {"team" : "ondemand656",
                       "url"  : "http://giraffesocialenterprises.org.uk/"}
            async with session.post(AmaraTask.WEBHOOKS_URL, json=payload) as response:
                response = await response.read()
                print("sending message: {} to url:{}\n".format(payload,
                                                               AmaraTask.WEBHOOKS_URL))
        return teams


def get_amara_init_info():
    global DEBUG
    global TIME_THRESHOLD

    DEBUG = os.getenv('DEBUG', "FALSE")
    if DEBUG == "FALSE":
        DEBUG = False
        print("DEBUG is false\n")
    else:
        print("DEBUG is true\n")
        DEBUG = True
        TIME_THRESHOLD = int(os.getenv('THRESHOLD', TIME_THRESHOLD))
        print("Found THRESHOLD: {}\n".format(TIME_THRESHOLD))

    AmaraTask.init_tasks()


def check_teams(event, context):
    get_amara_init_info()

    # Create client session that will ensure we dont open new connection
    # per each request.
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(check_amara_teams())
    teams = loop.run_until_complete(future)

    result = ''
    if not DEBUG:
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
    get_amara_init_info()

    tasks = []
    sem = asyncio.Semaphore(200)

    # Create client session that will ensure we dont open new connection
    # per each request.
    async with ClientSession(connector=TCPConnector(verify_ssl=False)) as session:

        teams = await auth_session_and_fetch_teams(session)

        print("Total teams to scrape: {}\n".format(len(teams)))

        for team in teams:
            url = activity_url_template.format(team.name)
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
    print(datetime.now())        

    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(run_task_checks())
    loop.run_until_complete(future)
    
    print(datetime.now())        

    response = {
        "statusCode": 200,
        "body": "complete"
    }
    return response
