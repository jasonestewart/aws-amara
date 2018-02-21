import json
import itertools
import boto3
from aiohttp import ClientSession, TCPConnector
import asyncio
import os
from datetime import datetime
from bs4 import BeautifulSoup
from html.parser import HTMLParser
import cProfile
import io
import pstats
from amara import AmaraUser, AmaraTask, AmaraTeam, AmaraJob

DEBUG = ""
DB = boto3.resource("dynamodb")
LOCAL = False
PROFILE = False

# time cutoff for interesting events in seconds (10 minutes)
TIME_THRESHOLD = -60 * 10


async def auth_session_and_fetch_teams(session):
    user = AmaraUser()

    teams = []

    if DEBUG:
        teams.append(AmaraTeam("demand-465", "/en/teams/demand-465/"))
        teams.append(AmaraTeam("ondemand060", "/en/teams/ondemand060/"))
        teams.append(AmaraTeam("ondemand616", "/en/teams/ondemand616/"))
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
                    self.cur_task.set_video_url(attr_dict['href'])
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
            task = AmaraTask(team,
                             "https://amara.org/en/teams/demand-465/activity/",
                             time,
                             "\n2 minutes ago\n\nOmnia Kamel\n  endorsed English subtitles for ETC_Layla_Arabic_SUBS_SL_170719.mp4 (transcriber)\n\n"
            )
            task.set_video_url('/en/videos/oZSRr0kN6GE2/info/etc_layla_arabic_subs_sl_170719mp4/')
            task.set_delta()
            a.append(task)
        elif "616" in team.name:
            task = AmaraTask(team,
                             "https://amara.org/en/teams/ondemand616/activity/",
                             time,
                             "\n2 minutes ago\n\nign_api added a video: Fe Review\n\n"
            )
            task.set_video_url('/en/videos/CFxLYlgjS67T/info/fe-review/?team=ondemand616')
            task.set_delta()
            a.append(task)
        else:
            task = AmaraTask(team,
                             "https://amara.org/en/teams/ondemand060/activity/",
                             time,
                             "\n2 minutes ago\n\nOmnia Kamel\n  endrosed English subtitles for ETC_Layla_Arabic_SUBS_SL_170719.mp4 (transcriber)\n\n"
            )
            task.set_video_url('/en/videos/8wxNgiJyLY0H/info/wwwyoutubecomwatchvgi1al50hxg8/?team=ondemand060')
            task.set_delta()
            a.append(task)

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

    AmaraTask.DEBUG = DEBUG
    AmaraUser.DEBUG = DEBUG
    AmaraJob.DEBUG = DEBUG
    AmaraTask.init_tasks()


def get_stored_pages(event, context):
    db_table = DB.Table("stored_pages")
    response = db_table.scan()
    pages = response["Items"]
    i = 0
    for page in pages:
        i += 1
        fname = "page{}.html".format(i)
        with open(fname, 'w') as f:
            f.write(page['page'])

    body = {
        "result"  : "found: {} pgaes".format(len(pages)),
    }
    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response


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

        print("Found tasks: {}\n".format(tasks))

        # Filter by terms
        jobs = []
        for task in tasks:
            job = task.filter()
            if job:
                jobs.append(job)

        print("Found jobs: {}\n".format(jobs))

        if jobs:
            await AmaraJob.handle_jobs(session, jobs)


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
