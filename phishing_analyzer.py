from email import policy
from email.parser import BytesParser
import sys
import re

file_path = "samples/2020-05-05-phishing-email-example-01.eml"


def parse_email(file_path):
    email = open(file_path, "rb")
    parser = BytesParser(policy=policy.default)
    result = parser.parsebytes(email.read())
    email.close()
    return result

def extract_headers(email):
    headers = {
        "from": email["From"],
        "to": email["To"],
        "subject": email["Subject"],
        "date": email["Date"],
        "return_path": email["Return-Path"]
    }

    return headers

def extract_received_headers(email):
    return email.get_all("Received")
    


print(extract_received_headers(parse_email(file_path)))
