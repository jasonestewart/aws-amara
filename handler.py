import json
from aiohttp import ClientSession, TCPConnector
import asyncio
import os
import re
from datetime import datetime
import io
from amara import AmaraUser, AmaraJob
import logging
# from IPython import embed

DEBUG = ""
VERBOSE = ""
LOCAL = False
PROFILE = False

logger = None


def get_amara_init_info():
    global DEBUG
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

    AmaraUser.DEBUG = DEBUG
    AmaraJob.DEBUG  = DEBUG


async def run_job_checks(event):
    logger.info("run_job_checks: start")

    assert(event['Records']
        and event['Records'][0]['eventVersion'] == '1.0'
        and event['Records'][0]["eventSource"]  == "aws:ses")

    ses = event['Records'][0]['ses']
    subject = ses['mail']['commonHeaders']['subject']
    
    job_re = re.compile(r".*AMARA JOB REQUEST.*TEAM (\d\d\d)")
    match = job_re.match(subject)
    team_num = ''
    if not match:
        logger.info("run_job_checks: non-amara email, end")
        return False
    else:
        team_num = match.group(1)

    # Create client session that will ensure we dont open new connection
    # per each request.
    async with ClientSession(connector=TCPConnector(verify_ssl=False)) as session:
        await AmaraUser.init(session)
        user = AmaraUser()
        
        await user.signup_for_job(team_num)

    logger.info("run_job_checks: end")


def amara_alert(event, context):
    get_amara_init_info()

    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(run_job_checks(event))
    loop.run_until_complete(future)

    response = {
        "statusCode": 200,
        "body": "complete"
    }
    return response
