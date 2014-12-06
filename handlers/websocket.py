from handlers.base import BaseHandler
import tornado.escape

__author__ = 'lionelschinckus'


class WebsocketSendNotificationHandler(BaseHandler):
    def get(self, *args, **kwargs):
        """

        """
        if self.get_argument("uuid") is not None and self.get_argument("message") is not None:
            for language in ['fr', 'nl', 'de', 'en']:
                subscriber = self.cache.get(str('subscribers.web.%s' % language))
                for subscriber in subscribers:
                    if subscriber.uuid == self.get_argument("uuid"):
                        message = {
                            "uuid": subscriber.uuid,
                            "code": 3,
                            "data": self.get_argument("message")
                        }
                        subscriber.write_message(tornado.escape.json_encode(message))
        else:
            self.send_error(404)