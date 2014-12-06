import logging
import uuid
import tornado.escape
import tornado.websocket

__author__ = 'lionelschinckus'


class TrafficSocketHandler(tornado.websocket.WebSocketHandler):
    """

    """

    def allow_draft76(self):
        # for iOS 5.0 Safari
        return True

    def open(self):
        self.application.logger.info("Websocket connection from %s" % self.ws_connection)
        self.uuid = str(uuid.uuid4())
        ack = {
            "uuid": self.uuid,
            "code": 2
        }
        self.write_message(tornado.escape.json_encode(ack))

    def on_close(self):
        subscribers = self.application.cache.get(str('subscribers.web.%s' % self.language))
        subscribers.remove(self)
        self.application.cache.set(str('subscribers.web.%s' % self.language), subscribers)

    @classmethod
    def publish(cls, channel, message):
        """
            Publish message to all subscribers on channel.
        """
        subscribers = cls.application.cache.get('subscribers.web.%s' % channel)
        for subscriber in subscribers:
            subscriber.write_message(tornado.escape.json_encode(message))

    @classmethod
    def test_message(cls, message):
        """
            Verify a subscribe/update message for wrong/missing values.
        """
        if (message["coords"] == None):
            raise AttributeError
        else:
            if message["coords"]["latitude"] is None or message["coords"]["longitude"] is None:
                raise AttributeError
            else:
                if (message["coords"]["latitude"] > 90
                    or message["coords"]["latitude"] < -90):
                    raise ValueError
                if (message["coords"]["longitude"] > 180
                    or message["coords"]["longitude"] < -180):
                    raise ValueError

        if message["area"] is None:
            raise AttributeError
        else:
            if message["area"] < 0:
                raise ValueError

        if message["language"] is None:
            raise AttributeError
        else:
            if message["language"] not in ["nl", "en", "de", "fr"]:
                raise ValueError


    def on_message(self, message):
        """
            Specific informations about messages
            Message IDs :
                1 SUBSCRIBE (from the client to the server)
                    When a user wants to subscribe to a specific traffic feed it sends this message
                    containing his preferences (area, coordinates and language) so he can be precisely notified.
                2 ACK (in both directions)
                    A simple acknowledgement message use to confirm reception on both sides.
                3 PUBLISH (from the server to the client)
                    Publish messages are used by the server to send data to the subscribers
                4 UPDATE
                    When a subscriber wants to update his config he can send an update message containing his
                    new configuration.
                5 ERROR
                    Simple error handling message
                6 BYE
        """

        self.application.logger.info("got message %r", message)

        try:
            parsed = tornado.escape.json_decode(message)
            # SUBSCRIBE OR UPDATE
            if int(parsed['code']) == 1:
                TrafficSocketHandler.test_message(parsed)

                self.uuid = str(uuid.uuid4())
                self.language = parsed['language']
                self.coords = parsed['coords']
                self.area = parsed["area"]

                subscribers = self.application.cache.get(str('subscribers.web.%s' % self.language))
                subscribers.append(self)
                self.application.cache.set(str('subscribers.web.%s' % self.language), subscribers)

                ack = {
                    "uuid": self.uuid,
                    "code": 2,
                    "message": "You successfully subscribed to beroads feed"
                }
                self.ws_connection.write_message(tornado.escape.json_encode(ack))
            elif int(parsed['code']) == 4:
                config = {
                    "language": parsed['language'],
                    "coords": parsed['coords'],
                    "area": parsed["area"]
                }
                for subscriber in self.application.cache.get(str('subscribers.web.{0:>s}'.format(self.language))):
                    if subscriber.uuid == parsed['uuid']:
                        subscriber.config = config
                        ack = {
                            "uuid": self.uuid,
                            "code": 2,
                            "message": "You updated your subscription to beroads feed"
                        }
                        self.ws_connection.write_message(tornado.escape.json_encode(ack))
            #ACK
            elif int(parsed['code']) == 2:
                self.application.logger.info("ACK received from subscriber " + self.ws_connection.uuid.value)

        except AttributeError as e:
            logging.exception(e)

            message = {
                'code': 5,
                'error_code': 0,
                'error_message': e.message
            }
            self.ws_connection.write_message(tornado.escape.json_encode(message))
        except ValueError as e:
            logging.exception(e)
            message = {
                'code': 5,
                'error_code': 0,
                'error_message': e.message
            }
            self.ws_connection.write_message(tornado.escape.json_encode(message))
        except Exception as e:
            logging.exception(e)
            message = {
                'code': 5,
                'error_code': 0,
                'error_message': e.message
            }
            self.ws_connection.write_message(tornado.escape.json_encode(message))