from email import policy
from email.parser import BytesParser
import sys
import re
import ipaddress

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

def extract_ips(received_headers):
    pattern = r"\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b"
    ips = []
    ip_dict = {"private":[], "loopback":[], "public":[]}

    for header in received_headers:
        ip_list = re.findall(pattern, header)
        for ipaddr in ip_list:
            try:
                ipaddress.ip_address(ipaddr)
                if ipaddr not in ips:
                    ips.append(ipaddr)
                    if ipaddress.ip_address(ipaddr).is_loopback:
                        ip_dict["loopback"].append(ipaddr)
                    elif ipaddress.ip_address(ipaddr).is_private:
                        ip_dict["private"].append(ipaddr)
                    else:
                        ip_dict["public"].append(ipaddr)
            except ValueError:
                pass
    return ip_dict

    


print(extract_ips(extract_received_headers(parse_email(file_path))))
