import time
from handlers.base import BaseHandler
import tornado.escape

__author__ = 'lionelschinckus'


class AppleSendNotificationHandler(BaseHandler):
    def get(self, *args, **kwargs):
        """

        """
        device_token = self.get_argument("device_token", None)
        message = self.get_argument("message", None)
        if not device_token or not message:
            self.send_error(404)
            return

        sent, details, _ = self.push_gateway.send_apns_notification(
            device_token=device_token,
            alert=str(message),
            custom={"source": "manual-test"},
        )
        if sent:
            self.set_status(200)
            self.write("Le message a pu etre envoye")
            return

        self.logger.error("APNS send test failed: %s", details)
        self.set_status(500)
        self.write("Le message n'a pas pu etre envoye: %s" % details)


class ApplePushNotificationServerHandler(BaseHandler):
    SUPPORTED_METHODS = ("POST")

    @staticmethod
    def _extract_coords(payload):
        coords = payload.get("coords")
        if not coords:
            raise AttributeError("coords is not set")

        latitude = coords.get("latitude", coords.get("lat"))
        longitude = coords.get("longitude", coords.get("lng"))
        if latitude is None or longitude is None:
            raise AttributeError("latitude/longitude is not set")

        latitude = float(latitude)
        longitude = float(longitude)
        if latitude > 90 or latitude < -90:
            raise ValueError("latitude is not valid")
        if longitude > 180 or longitude < -180:
            raise ValueError("longitude is not valid")
        return {"latitude": latitude, "longitude": longitude}

    def post(self, *args, **kwargs):
        """
            Add or update device info for push APNS
        """
        try:
            sandbox_mode = self.push_gateway.apns_environment

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

            data['area'] = int(data['area'])
            if data['area'] < 0:
                raise ValueError("area must be a positive value")

            normalized = {
                "device_token": data["device_token"],
                "language": data["language"],
                "area": data["area"],
                "coords": self._extract_coords(data),
                "timestamp": time.time(),
            }

            present = False
            cache_key = str('subscribers.apns.%s.%s' % (sandbox_mode, data['language']))
            legacy_cache_key = str('subscribers.apns.%s' % data['language'])
            subscribers = self.cache.get(cache_key)
            if not subscribers:
                subscribers = []
            for index, subscriber in enumerate(subscribers):
                if subscriber['device_token'] == data['device_token']:
                    subscribers[index] = normalized
                    present = True
                    break

            if not present:
                subscribers.append(normalized)

            self.cache.set(cache_key, subscribers)
            # Keep legacy key for old analytics endpoint.
            self.cache.set(legacy_cache_key, subscribers)
            self.set_status(200)
            self.write({"status": "ok"})

        except (AttributeError, ValueError) as e:
            self.logger.error(e)
            self.send_error(400)
        except Exception as e:
            self.logger.error(e)
            self.send_error(500)
