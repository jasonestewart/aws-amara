import json
import boto3
from aiohttp import ClientSession, TCPConnector
import asyncio
import os
from datetime import datetime
import cProfile
import io
import pstats
from amara import AmaraUser, AmaraJob
import logging
# from IPython import embed

DEBUG = ""
VERBOSE = ""
DB = boto3.resource("dynamodb")
LOCAL = False
PROFILE = False

logger = None


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


def get_amara_init_info():
    global DEBUG
    global LOCAL
    global PROFILE
    global logger

    logger = logging.getLogger('amara-handler')

    loglevel = os.getenv('LOGLEVEL', "WARN")
    numeric_level = getattr(logging, loglevel.upper(), None)
    try:
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
    except ValueError:
        logger.error("Bad loglevel %s", loglevel)
        loglevel = logging.WARN

    logger.setLevel(loglevel)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    root = logging.getLogger()
    root.handlers[0].setFormatter(formatter)

    logger.info("LOGLEVEL set to %s", loglevel)

    debug = os.getenv('DEBUG', "FALSE")
    if debug.upper() == "FALSE":
        DEBUG = False
        logger.info("DEBUG is false")
    else:
        logger.info("DEBUG is true")
        DEBUG = True

    local = os.getenv('LOCAL', "FALSE")
    if local.upper() == "FALSE":
        LOCAL = False
        logger.info("LOCAL is false")
    else:
        LOCAL = True
        logger.info("LOCAL is true")

    profile = os.getenv('PROFILE', "FALSE")
    if profile.upper() == "FALSE":
        PROFILE = False
        logger.info("PROFILE is false")
    else:
        PROFILE = True
        logger.info("PROFILE is true")

    AmaraUser.DEBUG = DEBUG
    AmaraJob.DEBUG  = DEBUG

    AmaraUser.LOCAL = LOCAL
    AmaraJob.LOCAL  = LOCAL


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


async def check_amara_teams():
    async with ClientSession(connector=TCPConnector(verify_ssl=False)) as session:
        await AmaraUser.init(session)
        user = AmaraUser()
        return user.get_current_jobs(), user.teams


def check_teams(event, context):
    get_amara_init_info()

    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(check_amara_teams())
    jobs, teams = loop.run_until_complete(future)

    # result = update_teams(teams)

    message = "Current jobs: {}\n".format(jobs)
    message += "Found teams: {}\n".format(len(teams))
    body = {
        "message" : message,
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response


async def bound_fetch(sem, team, user):
    async with sem:
        return await user.check_for_new_jobs(team)


async def run_job_checks():
    sem = asyncio.Semaphore(200)

    # Create client session that will ensure we dont open new connection
    # per each request.
    async with ClientSession(connector=TCPConnector(verify_ssl=False)) as session:
        await AmaraUser.init(session)
        user = AmaraUser()
        teams = user.teams

        if DEBUG and LOCAL:
            teams = AmaraUser.debug_teams()

        logger.info("Total teams to scrape: %i", len(teams))

        tasks = []
        for team in teams.values():
            task = asyncio.ensure_future(bound_fetch(sem, team, user))
            tasks.append(task)

        # Gather all futures
        tasks = asyncio.gather(*tasks)
        await tasks
        await user.handle_jobs()


def check_jobs(event, context):
    get_amara_init_info()

    if LOCAL:
        logger.info(datetime.now())

    if PROFILE:
        pr = cProfile.Profile()
        pr.enable()

    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(run_job_checks())
    loop.run_until_complete(future)

    if PROFILE:
        pr.disable()
        s = io.StringIO()
        sortby = 'cumulative'
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats()
        with open('stats.txt', 'w') as f:
            f.write(s.getvalue())

    if LOCAL:
        logger.info(datetime.now())

    response = {
        "statusCode": 200,
        "body": "complete"
    }
    return response
