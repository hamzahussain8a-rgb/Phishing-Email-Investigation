from email import policy
import email.utils
from email.parser import BytesParser
from email.header import decode_header
import sys
import re
import ipaddress
from urllib.parse import urlparse, parse_qs
import html
from html.parser import HTMLParser

file_path = "samples/2020-05-05-phishing-email-example-02.eml"


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

def analyze_sender(email_data):
    sender = email_data["From"]
    parsed_data = email.utils.parseaddr(sender)

    email_val = parsed_data[1]
    display_name = parsed_data[0]
    domain = email_val[email_val.find("@")+1:]
    comp = {"display_name" : display_name,"email": email_val,"domain":domain}
    return comp

def check_sender_mismatch(sender_info):
    displayn = sender_info.get("display_name")
    domain = sender_info.get("domain")
    flag = True
    pattern = r"\b[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\b"
    try:
        cleaned_displayn = re.findall(pattern, displayn)[0]
    except:
        return flag

    if cleaned_displayn.lower() == domain.lower():
        flag = False

    return flag

def decode_subject(email):
    piece = email["Subject"]
    if isinstance(piece, bytes):
        for pieces in piece:
            if pieces != None:
                final += pieces
        return final
    else:
        return piece
    
def analyze_subject(subject):
    suspicious_keywords = [
        "warning",
        "urgent",
        "final notice",
        "verify",
        "suspended",
        "password",
        "account"
    ]
    for keywords in suspicious_keywords:

        if keywords in subject.lower():
            return True
        else:
            return False


def analyze_return_path(email):
    print(email["Return-Path"])

def extract_body(email):
    return email.get_content()

def analyze_body(email):
    content = email.get_content_type()
    ishtml = False
    if content == "text/html":
        ishtml = True
    length = len(extract_body(email))

    result = {
        "content_type": content,
        "is_html": ishtml,
        "body_length": length
    }

    return result

class MyParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.data = []
        self.tags = []

    def handle_data(self, data):
        data = data.strip()
        if data:
            self.data.append(data)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


def extract_visible_text(email):
    body = extract_body(email)

    parser = MyParser()
    parser.feed(body)
    result = parser.data
    seperator = " "
    x = seperator.join(result)
    return x

def analyze_body_keywords(text):
    words_got = []
    suspicious_body_keywords = [
        "verify",
        "failed",
        "retrieve",
        "confirm",
        "password",
        "account",
        "login",
        "suspended",
        "urgent"
    ]
    for keywords in suspicious_body_keywords:
    
        if keywords in text.lower():
            words_got.append(keywords)

    return words_got

def analyze_html_body(email):
    body = extract_body(email)

    parser = MyParser()
    parser.feed(body)

    result = {
        "visible_text": " ".join(parser.data),
        "html_tags": parser.tags
    }

    return result

    
parsed_email = parse_email(file_path)

result = analyze_html_body(parsed_email)
print(result)




