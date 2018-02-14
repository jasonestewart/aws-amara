import json
import re
import boto3
from aiohttp import ClientSession
import itertools
import asyncio 
#import requests
import os
from pprint import pprint
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

activity_url_template = "https://amara.org/en/teams/{}/activity/"
DEBUG = ''
WEBHOOKS_URL = ''
LOGIN_URL = "https://amara.org/en/auth/login/?next=/"
POST_LOGIN_URL = "https://amara.org/en/auth/login_post/"
DB = boto3.resource("dynamodb")
response = ''

component_mapping = {
    'year': timedelta(weeks=52.25), 
    'month': timedelta(weeks=4.34524),
    'week': timedelta(weeks=1),
    'day': timedelta(days=1), 
    'hour': timedelta(hours=1), 
    'minute': timedelta(minutes=1)
}

TIME_THRESHOLD = -60 * 10 # time cutoff for interesting events in seconds (10 minutes)
#ALERT_TERMS = ['added a video', 'unassigned'] # What terms should trigger an alert
ALERT_TERMS = ['added a video', 'unassigned', r"endorsed.*(transcriber)"] # What terms should trigger an alert
ALERT_STRING = "|".join(ALERT_TERMS)
ALERT_REGEX = re.compile(ALERT_STRING)

def get_user():
    user = DB.Table("user")
    response = user.get_item(Key={"service_name" : "amara"})
    return response["Item"]

def timestring_to_minutes_delta(string):
    """ Parses e.g. 1 day, 5 hours ago as time delta"""

    def comp_to_delta(str_):
        """comp_to_delta('5 hours') returns datetime.timedelta(18000),"""
        str_ = str_.replace('ago','').strip().rstrip('s')
        numerator, comp = str_.split(' ')
        return int(numerator) * component_mapping[comp]

    delta = -sum([comp_to_delta(c) for c in string.split(',')], timedelta())
    return delta
    
async def auth_session_and_fetch_teams(session):
    login = get_user()
    username = login['user']
    password = login['pass']
    
    teams = []
    
    async with session.get(LOGIN_URL) as response:
        await response.read()
        crsf = response.cookies.get('csrftoken').value

    #response = session.get(url)    
    #crsf = response.cookies.get('csrftoken')

    auth = {
        'csrfmiddlewaretoken' : crsf, 
        'username' : username,
        'password' : password,
    }
    ref = {'referer' : LOGIN_URL}

    async with session.post(POST_LOGIN_URL, data=auth, headers=ref) as response:
        
        doc = await response.text()
        #response = session.post("https://amara.org/en/auth/login_post/", data=auth, headers=ref)
        #doc = response.text

        soup = BeautifulSoup(doc, 'html.parser')
        menu = soup.find(id='user-menu')

        for candidate in menu.find_next_sibling('ul').find_all('a'):

            if not candidate['href'].startswith('/en/teams/'):
                continue

            name = candidate['href'].split('/')[-2]

            if name == 'my': # Ignore the paged teams listings link.
                continue

            teams.append({'path': candidate['href'], 'name': name})

        return teams

async def fetch_team_activities(url, team, session):

    async with session.get(url) as response:

        doc = await response.text()
    #doc = response.text
        soup = BeautifulSoup(doc, 'html.parser')
        activity = soup.find(id='activity-list')

        a = []

        for item, time in [ (x, x.find(class_='timestamp').text) for x in activity.find_all('li')]:

            _delta = timestring_to_minutes_delta(time)

            if _delta.total_seconds() < TIME_THRESHOLD: #don't bother with tasks older than 20 minutes
                break
                                    
            a.append({
                'team': team,
                'url': url,
                'delta': _delta, 
                'activity': {
                    'time':time,
                    'text':item.text,
                }
            })
            break

        return a
    
def update_team(Table, team):
    Table.put_item(
        Item={"team_name" : team["name"], "team_url" : team["path"]
    })
    
def update_teams(teams):    
    info = DB.Table("Info")
    response = info.get_item(Key={"key_name" : "num_teams"})
    num_teams = int(response["Item"]["key_val"])
    
    teams_updated = 0
    if (len(teams) > num_teams):
        DBteams = DB.Table("teams")
        response = DBteams.scan()
        db_teams = response["Items"]
        
        team_dict = {}
        for team in db_teams:
            team_dict[team["team_name"]] = 1
            
        for team in teams:
            if team["name"] not in team_dict:
                teams_updated += 1
                update_team(DBteams, team)
        
        info.update_item(
            Key={"key_name" : "num_teams"},
            UpdateExpression='SET key_val = :val1',
            ExpressionAttributeValues={':val1': len(teams)}
        )
    return teams_updated
    
def init_teams(teams):    
    DBteams = DB.Table("teams")

    for team in teams:
        update_team(DBteams, team)

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
    session = requests.Session()

    teams = auth_session_and_fetch_teams(session)
    result = init_teams(teams)

    message = "Total teams to scrape: {}\n".format(len(teams))
    body = {
        "message" : message,
        "result" : result,
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
            payload = {"team": "ondemand656", "url":"http://giraffesocialenterprises.org.uk/"}
            async with session.post(WEBHOOKS_URL,json=payload) as response:
                response = await response.read()
                print("sending message: {} to url:{}\n".format(payload,WEBHOOKS_URL))
        return teams

def get_amara_init_info():
    global ALERT_STRING
    global ALERT_REGEX
    global WEBHOOKS_URL
    global DEBUG
    
    DEBUG = os.getenv('DEBUG', "FALSE")
    if DEBUG == "FALSE":
        DEBUG = False
        print("DEBUG is false\n")
    else:
        ALERT_STRING = os.getenv("ALERT", ALERT_STRING)
        ALERT_REGEX = re.compile(ALERT_STRING)
        print("found regex: {}".format(ALERT_STRING))
        print("DEBUG is true\n")
        DEBUG = True
        
    WEBHOOKS_URL = os.getenv('URL', "https://hooks.zapier.com/hooks/catch/738949/z8ql5t/")
    print("found webhooks url: {}".format(WEBHOOKS_URL))

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
        "result" : result,
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

    def term_filter(rx,text):
        return rx.search(text)
    
    tasks = []
    message = ""
    sem = asyncio.Semaphore(200)


    # Create client session that will ensure we dont open new connection
    # per each request.
    async with ClientSession() as session:

        teams = await auth_session_and_fetch_teams(session)

        print("Total teams to scrape: {}\n".format(len(teams)))

        for team in teams:
            url = activity_url_template.format(team['name'])
            task = asyncio.ensure_future(bound_fetch(sem, url, team, session))
            tasks.append(task)

        # Gather all futures
        team_activities = asyncio.gather(*tasks)
        
        # Flatten nested activities.    
        activities = list(itertools.chain(*await team_activities))
        
        print("tasks: {}\n".format(activities))

        # Filter by terms
        activities = list(filter(lambda a: term_filter(ALERT_REGEX,a['activity']['text']), activities))

        print("Total activities after filtering: {}\n".format(len(activities)))

        if len(activities) > 0:
            team_names = list(set(map(lambda a: a['team']['name'], activities)))
            for a in activities:
                payload = {"team": a['team']['name'], "url":a['url']}
                async with session.post(WEBHOOKS_URL,json=payload) as response:
                    response = await response.read()
                    print("sending message: {} to url:{}\n".format(payload,WEBHOOKS_URL))
                
    
    
    
def hello(event, context):
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(run_task_checks())
    loop.run_until_complete(future)
    response = {
        "statusCode": 200,
        "body": "complete"
    }
    return response