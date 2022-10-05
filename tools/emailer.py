from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import dns.resolver
import threading
import argparse
import smtplib
import logging
import string
import random
import email
import dkim
import os

dkim_private = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqCsndTEKmt3o5HlQXlz5bqNl6+1ILNmBcVnVFGYv8+w+n2A4
2NW0zIk178HIK9Krx3qvvFxnO1A2trRToNL602CRduDFaTuhwC4UA6r7r2A1vLbI
6rEb4jD9sgwwtgfmtMzy0EPW0oDfzlT5B34Wm242X28U6+5u1lsEuQ4p0iSCk9Rl
8feVzfQuAE73d0FWntY3EkGirANd6dTZXQNbSzYgSmaCCOPeauVpG2lmftQeQycM
mVHMnxImAFlfcZw7WCgTCSN1KjjnGtlYXGlP+zAr16Wbr/cWGi+HIu71jrA6cVX8
ZbBStThKEbW8M45kBmoogpirOLlKQ5U0p+oYpQIDAQABAoIBAALEIvQEiH4fpFMN
w8qpkNjHC0gkMQm70itBJQYe4C8M9cK9XHIEoeKzZxW4hEhkQLsZQ4a/plsNaLj8
oluE3OdZMUtZSyX9+x0kJOQijd1Godumzgs+Oo0v7RxeovZ7jsnujRfr5b60q/nC
4A3Ffy2zVGWheCChXWVdPeilWP7B4Cd7OgRxmAtkPc6dyN23gRP76+lcjobO/woH
1A1KqXHBbxUA1S81pLvTqfDDbyxmmWW8flYyOrJU5nmLgCQjvCoNLdy6x379C2jx
Su2RH2pC/2A8MvrsCtVDkDhiZlFJCU/+khYhXRNH0sn/2mG0p08R/CFaK39cIxAT
NL5LtYkCgYEA1thOxkMbOTXIom4pB/v164A3jTRnDq8QcZ3EZLpovvhjW69cDmJi
3Zr/nzlMeFZBgX+8J649VHQB/Vzw/N3Pj9gERWVbpYSau0IXGOTLnCYaaxMUXhe4
R1MjRI7bskey3g+v/3ctIwsjmImvAlN9tqA0Uzwf0FXyXSRjp9jyWw8CgYEAyGHn
G7lm7qVmoTcN1fPYSngmDNPEwbv+W6rZV2Wj71ddQWokDgAS09E6YreEAp7j4Jof
W/fE8KxYoph9W4na2Kv909X5Jxf0CxP2DHFt+VJf7ousf9Jr/ImvSqpAN3pwKF3g
Y1rutt+Jg/pWbYM0DtSRNsxWdOHp+PICVdUI4QsCgYEAyRlvouTtdn+BbYjvnymY
5vb9CI8kZ/o1yiOC0UYrBZY6aneaE1zEbenHm6Jmkb0rU6vc0selYIe11RJKAGcf
AeWRGePmBOg6bU1PkV2XuHFyCQey6OAK/bg0KtgNjLLQGktU0isbdNHYX8+AoQzF
f0w1rjN5E+lfExAct9+5+sECgYBPnlbttSUo/Z9hvzZIJLN0I3k674nmUIQoeCIT
j9cralMrgrkAtxbEAwZn4vMY93kj7Rk4uaIO3uv47w4gKQ5DuVMJsKNm3SWioTPK
jedcgVaMugK4ZytxFGQKDsulP4kBAQv/bkobb4Z8YiOlL9Snb96jH13a40jMGZzD
7fmxMQKBgQCq610XNThb0ChaH4H4jhO/k2a9lHZBLivsIxzbN6zzyTyB5eEJo+42
o3UIBW/3vEH1QPlacm+47wrmR2GfoGi2j9u8lJErdjjJcHXMkm3PO228cE/hyAlv
KO7eGH4OlPnNGDS6lsXT9gHKpT0MuNSI8ohhQTMluVq0SAoZE2ySig==
-----END RSA PRIVATE KEY-----
"""

def send_mail(testing_domain,receiver_domain,version_number,attack_number,id_number,message_text="Testing!",subject="Testing!", user="test",use_dkim=True):
    # resolve receiving domain to find out mail server
    try:
        receiver_domain_smtp_server = str(dns.resolver.resolve(receiver_domain, 'MX')[0].exchange)
    except Exception as e:
        print(e)
        logging.error(f"Didn't find an MX record for domain {receiver_domain}!")
        return


    # creating unique domain
    sender_domain = str(version_number).zfill(2) + str(attack_number).zfill(2) + str(id_number).zfill(6) + "." + testing_domain

    # create email message
    msg = MIMEMultipart()
    msg.attach(MIMEText(message_text, "plain"))
    msg["Subject"] = subject
    msg["From"] = user + "@" + sender_domain
    # since "test" is probably a known e-mail address we're using it as a receiver (if the e-mail address is not known, SPF, DKIM and DMARC may not be triggered)
    msg["To"] = user + "@" + receiver_domain
    msg["Date"] = email.utils.formatdate()
    msg["Message-ID"] = email.utils.make_msgid(domain=sender_domain)

    if use_dkim:
        # dkim sign the mail with the specific testing domain as a DKIM selector (This selector/domain will be queried for the public key)
        dkim_selector = "_dkim." + sender_domain
        headers = ["To", "From", "Subject", "Date","Message-ID"]
        sig = dkim.sign(
            message=msg.as_string().encode("ascii"),
            selector=str(dkim_selector).encode("ascii"),
            domain=sender_domain.encode("ascii"),
            privkey=dkim_private.encode("ascii"),
            include_headers=headers,)

        msg["DKIM-Signature"] = sig[len("DKIM-Signature: "):].decode()

    print("Sending the following e-mail:")
    print(msg)
    # send email message
    try:
        smtp_session = smtplib.SMTP(receiver_domain_smtp_server,timeout=10)
        smtp_session.send_message(msg)
        smtp_session.quit()
    except Exception as e:
        print(e)
        logging.error(f"There was an error while sending the email to {receiver_domain}!")
        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A script to trigger DNS requests by "exploiting" e-mail authentication methods (SPF, DKIM, DMARC).')
    parser.add_argument("--testing-domain", type=str, required=True, help="Domain to use a sending domain.")
    parser.add_argument("--domain-file", type=str, required=True, help="Path to domain file (domains seperated by newlines).")
    parser.add_argument("--message", type=str, default="Just checking!", help="Message to send.")
    parser.add_argument("--subject", type=str, default="Just checking!", help="Subject of the e-mail.")
    parser.add_argument("--user", type=str, default="test", help="User to send the e-mail to.")
    parser.add_argument("--version-number", type=int, default=0, help="Version number to use.")
    parser.add_argument("--start-method", type=int, default=0, help="Integer (starting at 0) of the analysis method to start with.")
    parser.add_argument("--start-id", type=int, default=0, help="Integer (starting at 0) of the id to start at.")
    args = parser.parse_args()

    try:
        domains = open(args.domain_file,"r").read().split("\n")
    except:
        logging.error("Please provide a valid domain list!")
        quit()

    print(f"Using domain {args.testing_domain}!")

    for domain in domains:
        if domain.strip() == "":
            break
        
        print("########## Testing {} in version {} with method offset {} and identification number {} ##########".format(domain,args.version_number,args.start_method,args.start_id))
        send_thread = threading.Thread(target=send_mail,args=(args.testing_domain,domain,args.version_number,args.start_method,args.start_id,args.message,args.subject,args.user,))
        send_thread.start()
        args.start_id += 1