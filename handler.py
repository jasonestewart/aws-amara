import os
import re
from amara import Amara
import logging
# from IPython import embed

logger = None


def setup_logging():
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


def amara_alert(event, context):
    setup_logging()

    logger.info("amara_alert: start")

    assert(event['Records']
        and event['Records'][0]['eventVersion'] == '1.0'
        and event['Records'][0]["eventSource"]  == "aws:ses")

    ses = event['Records'][0]['ses']
    subject = ses['mail']['commonHeaders']['subject']
    logger.debug("amara_alert: found email subject: %s", subject)

    match = re.match(r".*AMARA JOB REQUEST.*TEAM (\d\d\d)", subject)
    if not match:
        logger.info("amara_alert: non-amara job email, end")
        return False

    team_num = match.group(1)
    logger.debug("amara_alert: found amara team: %s", team_num)

    Amara.signup_for_job(team_num)

    logger.info("amara_alert: end")
