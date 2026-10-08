from email import policy
from email.parser import BytesParser
import sys
import re
import ipaddress
from urllib.parse import urlparse, parse_qs
import html

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

def extract_domains(email):
    pattern = r"\b[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\b"
    domains = []
    domain_list = []
    header = extract_headers(email)
    received_header = extract_received_headers(email)

    for key in header:
        value = str(header.get(key))
        temp = re.findall(pattern, value)
        for x in temp:
            domain_list.append(x)

    for head in received_header:
            temp = re.findall(pattern, head)
            for x in temp:
                domain_list.append(x)
    for d in domain_list:
        if d not in domains:
            try:
                ipaddress.ip_address(d)
            except ValueError:
                domains.append(d)

def extract_urls(email):
    data = email.get_payload()
    pattern = r'"?(https?://[^\s/$.?#].[^\s>"]*)'
    urls = re.findall(pattern, data)
    return urls

def analyze_urls(url_list):
    url_components = []
    pattern = r"^http://|^https://"
    for url in url_list:
        embedded_urls = []
        parsed = urlparse(url)
        qps = parse_qs(html.unescape(parsed.query))
        for qp in qps:
            if re.findall(pattern, qps.get(qp)[0]):
                embedded_urls.append(qps.get(qp)[0])
        url_component = {
            "url": url,
            "scheme": parsed.scheme,
            "domain": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query,
            "query_parameters": qps,
            "embedded_URL" : embedded_urls
        }
        url_components.append(url_component)

    return url_components


    
    
parsed_email = parse_email(file_path)

urls = extract_urls(parsed_email)

urlc = analyze_urls(urls)
print(urlc)





