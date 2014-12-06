import time
from handlers.base import BaseHandler
import tornado.escape

__author__ = 'lionelschinckus'


class GoogleCloudMessagingHandler(BaseHandler):
    def post(self, *args, **kwargs):
        """

        """
        try:
            self.logger.info("Request received from android device : " + self.request.body)
            data = tornado.escape.json_decode(str(self.request.body))
            if (data['registration_id'] is None or not len(data['registration_id'])):
                raise AttributeError("registration_id is not set")

            if data['language'] is None:
                raise AttributeError("language is not set")
            if data['language'] not in ['fr', 'nl', 'en', 'de']:
                raise AttributeError("language is not valid")

            if data['area'] is None or not len(data['area']):
                raise AttributeError("area is not set")

            if data['area'] < 0:
                raise ValueError("area must be a positive value")

            if data['coords'] is None or not len(data['coords']):
                raise AttributeError("coords is not set")

            if data["coords"]["lat"] is None or data["coords"]["lng"] is None:
                raise AttributeError('latitude is not set')
            else:
                if (data["coords"]["lat"] > 90
                    or data["coords"]["lat"] < -90):
                    raise ValueError("latitude is not valid")
                if (data["coords"]["lng"] > 180
                    or data["coords"]["lng"] < -180):
                    raise ValueError("longitude is not valid")

            present = False
            subscribers = self.cache.get(str('subscribers.gcm.%s' % data['language']))
            for subscriber in subscribers:
                if subscriber['registration_id'] == data['registration_id']:
                    subscriber = data
                    present = True

            if not present:
                data['timestamp'] = time.time()
                subscribers.append(data)
                self.cache.set(str('subscribers.gcm.%s' % data['language']), subscribers)

            self.set_status(200)

        except Exception as e:
            self.logger.error(e)
            self.send_error(500)