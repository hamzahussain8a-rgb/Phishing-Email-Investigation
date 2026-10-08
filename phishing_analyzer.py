from email import policy
from email.parser import BytesParser
from email.header import decode_header
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs
import hashlib
import html
import ipaddress
import json
import os
import re
import sys


SUSPICIOUS_SUBJECT_KEYWORDS = [
    "warning",
    "urgent",
    "final notice",
    "verify",
    "suspended",
    "password",
    "account",
    "security alert",
    "action required"
]

SUSPICIOUS_BODY_KEYWORDS = [
    "verify",
    "failed",
    "retrieve",
    "confirm",
    "password",
    "account",
    "login",
    "suspended",
    "urgent",
    "click",
    "update",
    "validate",
    "security",
    "immediately"
]


def parse_email(file_path):
    with open(file_path, "rb") as email_file:
        parser = BytesParser(policy=policy.default)
        return parser.parsebytes(email_file.read())


def extract_headers(email):
    return {
        "from": email["From"],
        "to": email["To"],
        "subject": email["Subject"],
        "date": email["Date"],
        "return_path": email["Return-Path"]
    }


def extract_received_headers(email):
    return email.get_all("Received") or []


def extract_ips(received_headers):
    pattern = r"\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}\b"

    ips = []
    ip_dict = {
        "private": [],
        "loopback": [],
        "public": []
    }

    for header in received_headers:
        ip_list = re.findall(pattern, header)

        for ipaddr in ip_list:
            try:
                ip = ipaddress.ip_address(ipaddr)

                if ipaddr not in ips:
                    ips.append(ipaddr)

                    if ip.is_loopback:
                        ip_dict["loopback"].append(ipaddr)

                    elif ip.is_private:
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

    headers = extract_headers(email)
    received_headers = extract_received_headers(email)

    for key in headers:
        value = str(headers.get(key))
        domain_list.extend(re.findall(pattern, value))

    for header in received_headers:
        domain_list.extend(re.findall(pattern, header))

    for domain in domain_list:
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            if domain not in domains:
                domains.append(domain)

    return domains


def extract_body(email):
    if email.is_multipart():
        body_parts = []

        for part in email.walk():
            if part.get_content_maintype() == "multipart":
                continue

            content_type = part.get_content_type()

            if content_type in ["text/plain", "text/html"]:
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass

        return "\n".join(body_parts)

    return email.get_content()


def extract_urls(email):
    body = extract_body(email)

    pattern = r'https?://[^\s"\'<>]+'

    urls = re.findall(pattern, body)

    cleaned_urls = []

    for url in urls:
        url = html.unescape(url)

        while url.endswith((">", '"', "'")):
            url = url[:-1]

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def analyze_urls(url_list):
    url_components = []

    embedded_pattern = r"https?://"

    for url in url_list:
        embedded_urls = []

        parsed = urlparse(url)

        query = html.unescape(parsed.query)
        qps = parse_qs(query)

        for value_list in qps.values():
            for value in value_list:
                if re.search(embedded_pattern, value):
                    embedded_urls.append(value)

        url_component = {
            "url": url,
            "scheme": parsed.scheme,
            "domain": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query,
            "query_parameters": qps,
            "embedded_URL": embedded_urls
        }

        url_components.append(url_component)

    return url_components


def decode_subject(subject):
    if not subject:
        return ""

    decoded_parts = []

    for part, encoding in decode_header(subject):
        if isinstance(part, bytes):
            try:
                decoded_parts.append(part.decode(encoding or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded_parts.append(part.decode("utf-8", errors="replace"))
        else:
            decoded_parts.append(part)

    return "".join(decoded_parts)


def analyze_subject(email):
    subject = email["Subject"]
    decoded_subject = decode_subject(subject)

    matches = []

    for keyword in SUSPICIOUS_SUBJECT_KEYWORDS:
        if keyword.lower() in decoded_subject.lower():
            matches.append(keyword)

    return {
        "original": subject,
        "decoded": decoded_subject,
        "suspicious_keywords": matches
    }


def analyze_sender(email):
    sender = email["From"]

    display_name, email_address = parseaddr(sender)

    domain = ""

    if "@" in email_address:
        domain = email_address.split("@", 1)[1]

    return {
        "display_name": display_name,
        "email": email_address,
        "domain": domain
    }


def check_sender_mismatch(sender_info):
    display_name = sender_info.get("display_name", "")
    sender_domain = sender_info.get("domain", "")

    pattern = r"\b[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\b"

    claimed_domains = re.findall(pattern, display_name)

    if not claimed_domains:
        return {
            "display_name": display_name,
            "sender_domain": sender_domain,
            "claimed_domain": None,
            "domain_mismatch": False,
            "reason": "No domain found in display name"
        }

    claimed_domain = claimed_domains[0]

    mismatch = claimed_domain.lower() != sender_domain.lower()

    return {
        "display_name": display_name,
        "sender_domain": sender_domain,
        "claimed_domain": claimed_domain,
        "domain_mismatch": mismatch
    }


class MyParser(HTMLParser):

    def __init__(self):
        super().__init__()

        self.data = []
        self.tags = []
        self.forms = []
        self.password_inputs = []
        self.hidden_inputs = []
        self.scripts = []
        self.links = []

    def handle_data(self, data):
        data = data.strip()

        if data:
            self.data.append(data)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)

        attributes = dict(attrs)

        if tag == "form":
            self.forms.append(attributes)

        elif tag == "input":

            input_type = attributes.get("type", "").lower()

            if input_type == "password":
                self.password_inputs.append(attributes)

            elif input_type == "hidden":
                self.hidden_inputs.append(attributes)

        elif tag == "script":
            self.scripts.append(attributes)

        elif tag == "a":
            self.links.append(attributes)


def extract_visible_text(email):
    body = extract_body(email)

    parser = MyParser()
    parser.feed(body)

    return " ".join(parser.data)


def analyze_body(email):
    content_type = email.get_content_type()

    body = extract_body(email)

    return {
        "content_type": content_type,
        "is_html": content_type == "text/html",
        "body_length": len(body)
    }


def analyze_body_keywords(text):
    words_got = []

    for keyword in SUSPICIOUS_BODY_KEYWORDS:
        if keyword.lower() in text.lower():
            words_got.append(keyword)

    return words_got


def analyze_html_body(email):
    body = extract_body(email)

    parser = MyParser()
    parser.feed(body)

    return {
        "visible_text": " ".join(parser.data),
        "html_tags": parser.tags,
        "forms": parser.forms,
        "password_inputs": parser.password_inputs,
        "hidden_inputs": parser.hidden_inputs,
        "scripts": parser.scripts,
        "links": parser.links
    }


def analyze_links(html_links):
    analyzed_links = []

    for link in html_links:

        href = link.get("href", "")
        visible_text = link.get("text", "")

        if href:
            parsed = urlparse(href)

            analyzed_links.append({
                "href": href,
                "domain": parsed.netloc,
                "scheme": parsed.scheme,
                "path": parsed.path,
                "query": parsed.query,
                "visible_text": visible_text
            })

    return analyzed_links


def analyze_html_links(email):
    body = extract_body(email)

    parser = MyParser()
    parser.feed(body)

    links = []

    for link in parser.links:

        href = link.get("href", "")

        if href:
            parsed = urlparse(href)

            links.append({
                "href": href,
                "domain": parsed.netloc,
                "scheme": parsed.scheme,
                "path": parsed.path,
                "query": parsed.query
            })

    return links


def analyze_attachments(email):

    attachments = []

    if not email.is_multipart():
        return attachments

    for part in email.walk():

        if part.is_multipart():
            continue

        filename = part.get_filename()

        if filename:

            payload = part.get_payload(decode=True)

            if payload is None:
                payload = b""

            sha256 = hashlib.sha256(payload).hexdigest()

            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": sha256
            })

    return attachments


def extract_iocs(email, ip_data, domains, url_data, attachments):

    iocs = {
        "ips": [],
        "domains": [],
        "urls": [],
        "file_hashes": []
    }

    for category in ip_data.values():
        for ip in category:
            if ip not in iocs["ips"]:
                iocs["ips"].append(ip)

    for domain in domains:
        if domain not in iocs["domains"]:
            iocs["domains"].append(domain)

    for url in url_data:
        value = url.get("url")

        if value and value not in iocs["urls"]:
            iocs["urls"].append(value)

    for attachment in attachments:
        hash_value = attachment.get("sha256")

        if hash_value and hash_value not in iocs["file_hashes"]:
            iocs["file_hashes"].append(hash_value)

    return iocs


def calculate_risk_score(
    sender_analysis,
    sender_mismatch,
    subject_analysis,
    body_keywords,
    html_analysis,
    url_analysis,
    attachments
):

    score = 0
    reasons = []

    if sender_mismatch.get("domain_mismatch"):
        score += 25
        reasons.append("Display name domain does not match sender domain")

    if subject_analysis["suspicious_keywords"]:
        score += 15
        reasons.append("Suspicious keywords found in subject")

    if body_keywords:
        score += 15
        reasons.append("Suspicious phishing language found in email body")

    if html_analysis["forms"]:
        score += 20
        reasons.append("HTML form detected")

    if html_analysis["password_inputs"]:
        score += 25
        reasons.append("Password input detected")

    if html_analysis["hidden_inputs"]:
        score += 10
        reasons.append("Hidden HTML input detected")

    if html_analysis["scripts"]:
        score += 15
        reasons.append("JavaScript detected in email")

    if url_analysis:
        score += 10
        reasons.append("URL detected in email")

    embedded_count = 0

    for url in url_analysis:
        embedded_count += len(url["embedded_URL"])

    if embedded_count:
        score += 15
        reasons.append("Embedded URL detected inside URL parameters")

    if attachments:
        score += 10
        reasons.append("Attachment detected")

    score = min(score, 100)

    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 40:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }


def build_report(email, file_path):

    headers = extract_headers(email)

    received_headers = extract_received_headers(email)

    ip_data = extract_ips(received_headers)

    domains = extract_domains(email)

    urls = extract_urls(email)

    url_analysis = analyze_urls(urls)

    sender_analysis = analyze_sender(email)

    sender_mismatch = check_sender_mismatch(sender_analysis)

    subject_analysis = analyze_subject(email)

    body_analysis = analyze_body(email)

    visible_text = extract_visible_text(email)

    body_keywords = analyze_body_keywords(visible_text)

    html_analysis = analyze_html_body(email)

    html_links = analyze_html_links(email)

    attachments = analyze_attachments(email)

    iocs = extract_iocs(
        email,
        ip_data,
        domains,
        url_analysis,
        attachments
    )

    risk = calculate_risk_score(
        sender_analysis,
        sender_mismatch,
        subject_analysis,
        body_keywords,
        html_analysis,
        url_analysis,
        attachments
    )

    report = {
        "file": os.path.basename(file_path),

        "headers": headers,

        "received_headers": received_headers,

        "sender_analysis": {
            "sender": sender_analysis,
            "mismatch_analysis": sender_mismatch
        },

        "subject_analysis": subject_analysis,

        "body_analysis": body_analysis,

        "body_keywords": body_keywords,

        "html_analysis": {
            "visible_text": visible_text,
            "tags": html_analysis["html_tags"],
            "forms": html_analysis["forms"],
            "password_inputs": html_analysis["password_inputs"],
            "hidden_inputs": html_analysis["hidden_inputs"],
            "scripts": html_analysis["scripts"],
            "links": html_links
        },

        "network_indicators": {
            "ips": ip_data,
            "domains": domains,
            "urls": url_analysis
        },

        "attachments": attachments,

        "iocs": iocs,

        "risk_assessment": risk
    }

    return report


def save_report(report, input_file):

    filename = os.path.splitext(
        os.path.basename(input_file)
    )[0]

    output_directory = "investigations"

    os.makedirs(output_directory, exist_ok=True)

    output_file = os.path.join(
        output_directory,
        filename + "_report.json"
    )

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return output_file


def print_summary(report):

    print("\n" + "=" * 60)
    print("PHISHING EMAIL INVESTIGATION")
    print("=" * 60)

    print(f"\nFile: {report['file']}")

    print("\nSender:")
    print(
        f"  {report['sender_analysis']['sender']['email']}"
    )

    print("\nSubject:")
    print(
        f"  {report['subject_analysis']['decoded']}"
    )

    print("\nSuspicious Subject Keywords:")
    print(
        f"  {report['subject_analysis']['suspicious_keywords']}"
    )

    print("\nSuspicious Body Keywords:")
    print(
        f"  {report['body_keywords']}"
    )

    print("\nPublic IPs:")
    print(
        f"  {report['network_indicators']['ips']['public']}"
    )

    print("\nDomains:")
    print(
        f"  {report['network_indicators']['domains']}"
    )

    print("\nURLs:")
    for url in report["network_indicators"]["urls"]:
        print(f"  {url['url']}")

    print("\nSender Domain Mismatch:")
    print(
        f"  {report['sender_analysis']['mismatch_analysis']['domain_mismatch']}"
    )

    print("\nHTML Forms:")
    print(
        f"  {len(report['html_analysis']['forms'])}"
    )

    print("\nPassword Inputs:")
    print(
        f"  {len(report['html_analysis']['password_inputs'])}"
    )

    print("\nAttachments:")
    print(
        f"  {len(report['attachments'])}"
    )

    print("\nRisk Assessment:")
    print(
        f"  Score: {report['risk_assessment']['score']}/100"
    )

    print(
        f"  Verdict: {report['risk_assessment']['verdict']}"
    )

    print("\nReasons:")

    for reason in report["risk_assessment"]["reasons"]:
        print(f"  - {reason}")

    print("\n" + "=" * 60)


def analyze_file(file_path):

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    try:
        email = parse_email(file_path)

        report = build_report(
            email,
            file_path
        )

        output_file = save_report(
            report,
            file_path
        )

        print_summary(report)

        print(f"\nReport saved to: {output_file}")

    except Exception as error:
        print(f"Error analyzing file: {error}")


def main():

    if len(sys.argv) < 2:

        print(
            "Usage: python phishing_analyzer.py <email.eml>"
        )

        print(
            "Example: python phishing_analyzer.py samples/example-01.eml"
        )

        return

    file_path = sys.argv[1]

    analyze_file(file_path)


if __name__ == "__main__":
    main()