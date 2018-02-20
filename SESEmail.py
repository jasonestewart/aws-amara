import boto3
from botocore.exceptions import ClientError


class SESEmail(object):
    """Class to encapsulate sending SES emails"""
    SENDER = "Jason Stewart <jason@giraffesocialenterprises.org.uk>"
    RECIPIENT = "jason@giraffesocialenterprises.org.uk"
    AWS_REGION = "us-east-1"
    SUBJECT = ""
    BODY_HTML = ""
    CHARSET = "UTF-8"
    client = boto3.client('ses', region_name=AWS_REGION)

    def __init__(self, subject=SUBJECT, sender=SENDER, recipient=RECIPIENT,
                 body=BODY_HTML, charset=CHARSET):
        self.subject = subject
        self.sender = sender
        self.recipient = recipient
        self.charset = charset
        self.body = body

    def send_email(self):
        # Try to send the email.
        try:
            # Provide the contents of the email.
            response = SESEmail.client.send_email(
                Destination={
                    'ToAddresses': [
                        self.recipient,
                    ],
                },
                Message={
                    'Body': {
                        'Html': {
                            'Charset': self.charset,
                            'Data': self.body,
                        },
                    },
                    'Subject': {
                        'Charset': self.charset,
                        'Data': self.subject,
                    },
                },
                Source=self.sender,
            )
        # Display an error if something goes wrong.
        except ClientError as e:
            print(e.response['Error']['Message'])
        else:
            print("Email sent! Message ID:"),
            print(response['ResponseMetadata']['RequestId'])
