#!/bin/env python3

from datetime import datetime
from enum import Enum
from cryptography import x509
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

def check_ssl_cert(context, hostname, today, expiration_type):
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print("Domain:", hostname)
            print("SSL/TLS version:", ssock.version())

            # Get cert in DER format
            data = ssock.getpeercert(True)

            # Convert cert to PEM format
            pem_data = ssl.DER_cert_to_PEM_cert(data)

            # pem_data in a string. Convert to bytes using str.encode()
            # Extract cert info
            cert_data = x509.load_pem_x509_certificate(str.encode(pem_data))

            print("Certificate expiration date:", cert_data.not_valid_after)
            date_compare(cert_data.not_valid_after, today, expiration_type)

def check_domain_expiration(hostname, today, expiration_type):
    domain = whois.whois(hostname)
    if isinstance(domain.expiration_date, list):
        print("Domain expiration date:", domain.expiration_date[0])
        date_compare(domain.expiration_date[0], today, expiration_type)
        # Case for when multiple domain expiration dates are found.
        # print("Found", len(domain.expiration_date), "domain expiration dates.")
        # for date in domain.expiration_date:
        #     print("Domain expiration date:", date)
        #     date_compare(date, today, expiration_type)
    else:
        print("Domain expiration date:", domain.expiration_date)
        date_compare(domain.expiration_date, today, expiration_type)

def date_compare(date, today, expiration_type):
    if date < today:
        if expiration_type == ExpirationType.DOMAIN.name:
            print("Domain is expired!")
        elif expiration_type == ExpirationType.CERTIFICATE.name:
            print("Certificate is expired!")
        delta_time = today - date
        print("Expired for", delta_time)
    else:
        if expiration_type == ExpirationType.DOMAIN.name:
            print("Domain is valid.")
        elif expiration_type == ExpirationType.CERTIFICATE.name:
            print("Certificate is valid.")
        delta_time = date - today
        print("Still valid for", delta_time)
        if delta_time.days < notification_delta_days:
            notify_user()

def notify_user():
    # Notify user of expiration
    print("Notification condition met")

if __name__ == '__main__':
    main()