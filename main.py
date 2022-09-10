#!/bin/env python3

from datetime import datetime
from enum import Enum
from cryptography import x509
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
import socket
import ssl
import whois

class ExpirationType(Enum):
    DOMAIN = 1
    CERTIFICATE = 2

# https://www.ssl.com/sample-valid-revoked-and-expired-ssl-tls-certificates/
domains = ["expired-rsa-dv.ssl.com", "expired-ecc-dv.ssl.com", "test-dv-rsa.ssl.com", "test-dv-ecc.ssl.com"]

# Example: You want to be notified 30, 60, or 90 days before your certificate or domain expires.
notification_delta_days = 30

def main():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    current_datetime = datetime.now()
    print("Current date:", current_datetime, "\n")

    for domain in domains:
        check_ssl_cert(context, domain, current_datetime, ExpirationType.CERTIFICATE.name)
        check_domain_expiration(domain, current_datetime, ExpirationType.DOMAIN.name)
        print()

def check_ssl_cert(context, domain, today, expiration_type):
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            print("Domain:", domain)
            print("SSL/TLS version:", ssock.version())

            # Get cert in DER format
            data = ssock.getpeercert(True)

            # Convert cert to PEM format
            pem_data = ssl.DER_cert_to_PEM_cert(data)

            # pem_data in a string. Convert to bytes using str.encode()
            # Extract cert info
            cert_data = x509.load_pem_x509_certificate(str.encode(pem_data))

            print("Certificate expiration date:", cert_data.not_valid_after)
            compare_date_and_build_msg(cert_data.not_valid_after, today, expiration_type, domain)

def check_domain_expiration(domain, today, expiration_type):
    domain = whois.whois(domain)
    if isinstance(domain.expiration_date, list):
        print("Domain expiration date:", domain.expiration_date[0])
        compare_date_and_build_msg(domain.expiration_date[0], today, expiration_type, domain)
        # Case for when multiple domain expiration dates are found.
        # print("Found", len(domain.expiration_date), "domain expiration dates.")
        # for date in domain.expiration_date:
        #     print("Domain expiration date:", date)
        #     date_compare(date, today, expiration_type)
    else:
        print("Domain expiration date:", domain.expiration_date)
        compare_date_and_build_msg(domain.expiration_date, today, expiration_type, domain)

def compare_date_and_build_msg(expiration_date, today, expiration_type, domain):
    msg = ""
    if expiration_date < today:
        delta_time = today - expiration_date
        if expiration_type == ExpirationType.DOMAIN.name:
            print("Domain is expired!")
            msg += "Domain: " + domain + " has been expired " + "for " + str(delta_time) + "\n"
        elif expiration_type == ExpirationType.CERTIFICATE.name:
            print("Certificate is expired!")
            msg += "Certificate for domain: " + domain + " has been expired " + "for " + str(delta_time) + "\n"
        print("\nEMAIL MESSAGE:")
        notify_user(msg)
    else:
        delta_time = expiration_date - today
        if expiration_type == ExpirationType.DOMAIN.name:
            print("Domain is valid.")
            msg += "Domain: " + domain + " is still valid " + "for " + str(delta_time) + "\n"
        elif expiration_type == ExpirationType.CERTIFICATE.name:
            print("Certificate is valid.")
            msg += "Certificate for domain: " + domain + " is still valid " + "for " + str(delta_time) + "\n"
        
        if delta_time.days < notification_delta_days:
            print("Expiration date is within " + str(notification_delta_days) + " days.\n")
            print("EMAIL MESSAGE:")
            notify_user(msg)

def notify_user(msg):
    # Notify user of expiration
    print("Sending notification email...")
    print(msg)
    message = Mail(
    from_email="",
    to_emails="",
    subject="",
    html_content=msg)
    try:
        # Be sure the environment variable is being set or you will get a HTTP Error 401: Unauthorized.
        # print("sg", os.environ.get("SENDGRID_API_KEY"))
        sg = SendGridAPIClient(os.environ.get("SENDGRID_API_KEY"))
        response = sg.send(message)
        # print(response.status_code)
        # print(response.body)
        # print(response.headers)
    except Exception as e:
        print(e.message)

if __name__ == "__main__":
    main()