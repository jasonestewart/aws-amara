import os
import re
from amara import Amara
import logging
# from IPython import embed
import boto3
from email import policy
from email.parser import BytesParser
import lxml.html

s3 = boto3.resource('s3')

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
        and event['Records'][0]['eventVersion'] == '2.0'
        and event['Records'][0]["eventSource"]  == "aws:s3")

    s3_rec = event['Records'][0]['s3']
    bucket = s3_rec['bucket']['name']
    key = s3_rec['object']['key']
    logger.debug("amara_alert: found s3 bucket: %s, key: %s", bucket, key)

    response = s3.Object(bucket, key).get()
    email_bytes = response['Body'].read()
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
    subject = msg['subject']
    match = re.search(r"AMARA JOB REQUEST.*TEAM (\d\d\d)", subject)
    if not match:
        logger.info("amara_alert: non-amara job email, end")
        return False

    team_num = match.group(1)
    logger.debug("amara_alert: found amara team: %s", team_num)

    html_body = msg.get_body(preferencelist=('html', 'plain')).get_content()

    root = lxml.html.fromstring(html_body)
    hrefs = root.xpath('//a/@href')
    logger.debug("amara_alert: found links: %s", hrefs)

    link = None
    for h in hrefs:
        if re.search(team_num + r".*assignments", h):
            link = h
            break

    logger.debug("amara_alert: found link: %s", link)

    Amara.signup_for_job(team_num, link)

    logger.info("amara_alert: end")
