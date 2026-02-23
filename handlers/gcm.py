import time
from handlers.base import BaseHandler
import tornado.escape

__author__ = 'lionelschinckus'


class FCMRegistrationHandler(BaseHandler):
    SUPPORTED_METHODS = ("POST",)

    @staticmethod
    def _extract_token(payload):
        token = payload.get("fcm_token") or payload.get("registration_id") or payload.get("token")
        if not token:
            raise AttributeError("FCM token is not set")
        return token

    @staticmethod
    def _extract_coords(payload):
        coords = payload.get("coords")
        if not coords:
            raise AttributeError("coords is not set")

        lat = coords.get("lat", coords.get("latitude"))
        lng = coords.get("lng", coords.get("longitude"))
        if lat is None or lng is None:
            raise AttributeError("latitude/longitude is not set")

        lat = float(lat)
        lng = float(lng)
        if lat > 90 or lat < -90:
            raise ValueError("latitude is not valid")
        if lng > 180 or lng < -180:
            raise ValueError("longitude is not valid")
        return {"lat": lat, "lng": lng}

    def post(self, *args, **kwargs):
        """

        """
        try:
            request_body = self.request.body.decode("utf-8")
            self.logger.info("Request received from android device : %s", request_body)
            data = tornado.escape.json_decode(self.request.body)
            token = self._extract_token(data)

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
                "registration_id": token,
                "fcm_token": token,
                "language": data["language"],
                "area": int(data["area"]),
                "coords": self._extract_coords(data),
                "timestamp": time.time(),
            }
            if "points" in data:
                normalized["points"] = data["points"]

            present = False
            cache_key = str('subscribers.fcm.%s' % data['language'])
            legacy_cache_key = str('subscribers.gcm.%s' % data['language'])
            subscribers = self.cache.get(cache_key)
            if subscribers is None:
                subscribers = self.cache.get(legacy_cache_key)
            if not subscribers:
                subscribers = []

            for index, subscriber in enumerate(subscribers):
                existing_token = subscriber.get('fcm_token') or subscriber.get('registration_id')
                if existing_token == token:
                    subscribers[index] = normalized
                    present = True
                    break

            if not present:
                subscribers.append(normalized)

            # Keep legacy key for dashboards/analytics compatibility.
            self.cache.set(cache_key, subscribers)
            self.cache.set(legacy_cache_key, subscribers)

            self.set_status(200)
            self.write({"status": "ok"})

        except (AttributeError, ValueError) as e:
            self.logger.error(e)
            self.send_error(400)
        except Exception as e:
            self.logger.error(e)
            self.send_error(500)


class GoogleCloudMessagingHandler(FCMRegistrationHandler):
    """Legacy endpoint alias for old clients."""
