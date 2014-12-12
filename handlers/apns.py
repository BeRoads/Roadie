import logging
import time
from apns_clerk import *
from handlers.base import BaseHandler
import tornado.escape

__author__ = 'lionelschinckus'


class AppleSendNotificationHandler(BaseHandler):
    def get(self, *args, **kwargs):
        """

        """
        if self.get_argument("device_token") is not None and self.get_argument("message") is not None:
            message = str(self.get_argument("message"))
            device_token = self.get_argument("device_token")
            try:
                payload = Message(tokens=device_token, alert=message, sound="default", badge=1)
                result = self.apns.send(payload)
                self.write("Le message a pu etre envoye")
                self.set_status(200)
            except:
                # if the payload is too large, we chomp the alert content
                self.logger.error("Check your network, I could not connect to APNs")
                print("Check your network, I could not connect to APNs")
            else:
                    for token, (reason, explanation) in result.failed.items():
                        print("token %s, reason : %s, explanation : %s"%(token, result, explanation))
                        self.write("Le message n'a pas pu etre envoye, raison : %s, explication : %s"%(reason, explanation))
                        self.set_status(500)

                    for reason, explanation in result.errors:
                        print("reason %s, explanation : %s" % (result, explanation))
                        self.write("Le message n'a pas pu etre envoye, raison : %s, explication : %s"%(reason, explanation))
                        self.set_status(500)
                    if result.needs_retry():
                        # extract failed tokens as new message
                        message = payload.retry()
                        print("Need to be retry")
                        self.write("Need to be retry ...")
        else:
            self.send_error(404)


class ApplePushNotificationServerHandler(BaseHandler):
    SUPPORTED_METHODS = ("POST")

    def post(self, *args, **kwargs):
        """
            Add or update device info for push APNS
        """
        try:
            if not self.config['push']['apns_sandbox_mode']:
                sandbox_mode = "production"
            else:
                sandbox_mode = "sandbox"

            self.logger.info("Request received from iDevice : %s" % self.request.body.decode("utf-8"))
            data = tornado.escape.json_decode(self.request.body)
            if data['device_token'] is None or not len(data['device_token']):
                raise AttributeError("device_token is not set")

            if data['language'] is None:
                raise AttributeError("language is not set")
            if data['language'] not in ['fr', 'nl', 'en', 'de']:
                raise AttributeError("language is not valid")

            if data['area'] is None:
                raise AttributeError("area is not set")

            if data['area'] < 0:
                raise ValueError("area must be a positive value")

            if data['coords'] is None or not len(data['coords']):
                raise AttributeError("coords is not set")

            if data["coords"]["latitude"] is None or data["coords"]["longitude"] is None:
                raise AttributeError('latitude is not set')
            else:
                if float(data["coords"]["latitude"]) > 90 or float(data["coords"]["latitude"]) < -90:
                    raise ValueError("latitude is not valid")
                else:
                    data['coords']['latitude'] = float(data['coords']['latitude'])
                if float(data["coords"]["longitude"]) > 180 or float(data["coords"]["longitude"]) < -180:
                    raise ValueError("longitude is not valid")
                else:
                    data['coords']['longitude'] = float(data['coords']['longitude'])

            present = False
            subscribers = self.cache.get(str('subscribers.apns.%s.%s' % (sandbox_mode, data['language'])))
            if not subscribers:
                subscribers = []
            for subscriber in subscribers:
                if subscriber['device_token'] == data['device_token']:
                    subscriber = data
                    present = True

            if not present:
                data['timestamp'] = time.time()
                subscribers.append(data)

            self.cache.set(str('subscribers.apns.%s.%s' % (sandbox_mode, data['language'])), subscribers)
            self.set_status(200)

        except Exception as e:
            self.logger.error(e)
            self.send_error(500)