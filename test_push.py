from apnsclient import *
import os

try:
    cert_path = os.path.join(os.path.dirname(__file__), 'beroads.cert')
    key_path = os.path.join(os.path.dirname(__file__), 'beroads.key')

    device_token = "1fa5768e51239294ea6ec93ccdf98a7664161c22bba5157999c910c1b22d892f"
    session = Session()
    certificate = Certificate(cert_file=cert_path, key_file=key_path, passphrase="lio")
    con = session.get_connection("push_production", certificate=certificate)
    message = Message([device_token], alert="My message", badge=10)

    # Send the message.
    srv = APNs(con)
    res = srv.send(message)

    # Check failures. Check codes in APNs reference docs.
    for token, reason in res.failed.items():
        code, errmsg = reason
        print "Device faled: {0}, reason: {1}".format(token, errmsg)

    # Check failures not related to devices.
    for code, errmsg in res.errors:
        print "Error: ", errmsg

    # Check if there are tokens that can be retried
    if res.needs_retry():
        # repeat with retry_message or reschedule your task
        retry_message = res.retry()

except Exception as e:
    print e.message