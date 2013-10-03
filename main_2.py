# -*- coding: utf-8 -*-

import tornado.escape
import tornado.ioloop
from tornado.options import options, define
import tornado.web
import tornado.websocket
import tornado.gen
from tornado.iostream import StreamClosedError

import logging
import os
import requests
from requests_oauthlib import OAuth1
import json
import re
import torndb
import time
import base64
import hashlib
import subprocess
import numpy as np
from math import radians, cos, sin, asin, sqrt, atan2
import uuid

from gcm import *
from APNSWrapper import *
import twitter

def require_basic_auth(handler_class):
    # Should return the new _execute function, one which enforces
    # authentication and only calls the inner handler's _execute() if
    # it's present.
    def wrap_execute(handler_execute):
        # I've pulled this out just for clarity, but you could stick
        # it in _execute if you wanted.  It returns True iff
        # credentials were provided.  (The end of this function might
        # be a good place to see if you like their username and
        # password.)
        def require_basic_auth(handler, kwargs):
            auth_header = handler.request.headers.get('Authorization')
            if auth_header is None or not auth_header.startswith('Basic '):
                # If the browser didn't send us authorization headers,
                # send back a response letting it know that we'd like
                # a username and password (the "Basic" authentication
                # method).  Without this, even if you visit put a
                # username and password in the URL, the browser won't
                # send it.  The "realm" option in the header is the
                # name that appears in the dialog that pops up in your
                # browser.
                handler.set_status(401)
                handler.set_header('WWW-Authenticate', 'Basic realm=Restricted')
                handler._transforms = []
                handler.finish()
                return False
                # The information that the browser sends us is
            # base64-encoded, and in the format "username:password".
            # Keep in mind that either username or password could
            # still be unset, and that you should check to make sure
            # they reflect valid credentials!
            auth_decoded = base64.decodestring(auth_header[6:])
            username, password = auth_decoded.split(':', 2)
            kwargs['basicauth_user'], kwargs['basicauth_pass'] = username, password
            return True

        # Since we're going to attach this to a RequestHandler class,
        # the first argument will wind up being a reference to an
        # instance of that class.
        def _execute(self, transforms, *args, **kwargs):
            if not require_basic_auth(self, kwargs):
                return False
            return handler_execute(self, transforms, *args, **kwargs)

        return _execute

    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class

PRECISION = 10
R = 6367
def haversine(a, b):
    """
    Calculate the great circle distance between two points
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians
    lon1, lat1, lon2, lat2 = map(radians, [a['longitude'], a['latitude'], b['longitude'], b['latitude']])
    # haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    km = R * c
    return km

def to_cartesian(latitude, longitude):
    """

    """
    x = R * cos(lattitude) * cos(longitude)
    y = R * cos(latitude) * sin(longitude)
    z = R * sin(latitude)
    return {'x' : x, 'y' :  y, 'z' : z}

def from_cartesian(a):
    """
        a is a cartesian coordinates array [x, y, z]
    """
    latitude = asin(a['z'] / R)
    longitude = atan2(a['y'], a['x'])
    return {'latitude' : latitude, 'longitude' : longitude}

def nearest_point_great_circle(a, b, c):
    """

    """
    d = np.array(to_cartesian(a['latitude'], a['longitude']))
    e = np.array(to_cartesian(b['latitude'], b['longitude']))
    f = np.array(to_cartesian(c['coords']['latitude'], c['coords']['longitude']))

    G = np.cross(d, e)
    H = np.cross(f, G)
    t = np.cross(G, H)
    t *= R
    return from_cartesian(t)

def on_segment(a, b, t):
    """

    """
    return abs(haversine(a,b) - haversine(a,t) - haversine(b, t)) < PRECISION

def nearest_point_segment(a, b, c):
    """

    """
    t = nearest_point_great_circle(a,b,c)
    if on_segment(a,b,t):
        return t
    return (a if haversine(a,c) < haversine(b,c) else c)


logging.basicConfig(filename='beroads.log', level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

define("ip", default="0.0.0.0", help="listen to the given ip")
define("port", default=8080, help="run on the given port", type=int)
define("mysql_host", default="localhost", help="database host")
define("mysql_database", default="beroads", help="database name")
define("mysql_user", default="root", help="database user")
define("mysql_password", default="YiOO9zQFcixYI", help="database password")
define("package_query", default="SELECT * FROM package WHERE package_name = %s",
    help="database request to get package by package name")
define("max_subscribers", default=0, help="")
define("webcams_directory", default="/var/www/vhosts/beroads/public_html/dashboard/webcams/", help="")
define("webcams_fetch_frequency", default=900000, help="")
define("traffic_fetch_frequency", default=900000, help="")
define("apns_certificate", "beroads.pem")
define("gcm_api_key", "AIzaSyC_UN1QUzNZLsyWzCbL2HIDglgN92b5FxY")
define("apns_sandbox_mode", True)

define("twitter_keys", {
    "main" : {
        "consumer_key" : "iteQq6eatYKJwTKfcHcyFQ",
        "consumer_secret" : "m1V9bs5q1XTejV1MqM6rmGqonNeARoCqS5aO33TxE",
        "access_token_key" : "351441174-ykJ5w2V5zCcilP3nHb4ihCWXMkPdM03VuAd9s9w2",
        "access_token_secret" : "d1KIcR6ZYxU5c6Pf7uqjQ88gb46yHyBEEGGY3hrw2Y"
    },
    "fr" : {
        "consumer_key" : "lekthlGntaYeyQFkyXCbQ",
        "consumer_secret" : "6uABinIZpR5YGrvFeLS6pp2EyF8dXgJEvzddfhU",
        "access_token_key" : "1890991999-91RGMHrTrCgO8Ll9s91zrJ6XZrakVvlLjnA4pXR",
        "access_token_secret" : "hMhmFWwbUXqON7rwDaVogFm9ZQsO5Zr87VhosxDmg"
    },
    "nl" : {
        "consumer_key" : "gwC5BwkZxXaS6KEzRQRHow",
        "consumer_secret" : "NYHcj5gII0CwrY49FuwjWqpSWHfRRQyQVYJta0SPhQ",
        "access_token_key" : "1890943374-mIlGMbcF5Wnz38UyCvIuP0c0UwsEYdS9Zs3Xsr1",
        "access_token_secret" : "teHOaVcNY69itdoAnyGV3yuoKtMCaxUJ0ZoV98jwSU"
    },
    "de" : {
        "consumer_key" : "cNX9Fazas6rFyvBZXyEQ",
        "consumer_secret" : "mDcEC5lulc6mXxnBCZI7PppJOhRLY3cu245Mlb00Yh0",
        "access_token_key" : "1890967974-nHrVYU3lnHcGMaYnDjvr8jrQpnDiJZ9aVONs4MB",
        "access_token_secret" : "E2ktf744h3DWFQtPaeeZQbQCILAmcalRdblspAZZd8Q"
    },
    "en" : {
        "consumer_key" : "9O4HYykiJYRaVe2Gkrduw",
        "consumer_secret" : "JF2Ngwhk8IhINvNL9lQwC6G3bIfvmrfgeW8rOakqq7U",
        "access_token_key" : "1890992048-UOZYhDcsk7hffKhPs5Dyd15mpKBD3BBwpJ0cY23",
        "access_token_secret" : "9aXlfLtLQTGCHhUnetskrqumD9XHNUkiP0yubE"
    }
})

class Application(tornado.web.Application):
    def __init__(self):
        settings = dict(
            cookie_secret="5725af95ef74805b753cd3689bb3393681e02ce6",
            static_path="static",
            xsrf_cookies=False,
            server_ip=options.ip
        )

        handlers = [
            (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": "static"}),
            (r"/socket", TrafficSocketHandler),
            (r"/socket/send", WebsocketSendNotificationHandler),
            (r"/", DashboardHandler),
            (r"/gcm", GoogleCloudMessagingHandler),
            (r"/apns", ApplePushNotificationServerHandler),
            (r"/apns/send", AppleSendNotificationHandler),
            (r"/analytics/subscribers/([0-9a-zA-Z_\-]+)", AnalyticsSubscribersHandler),
            (r"/analytics/os/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)", AnalyticsOSHandler),
            (r"/analytics/language/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)", AnalyticsLanguageHandler),
            (r"/analytics/browser/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)", AnalyticsBrowserHandler),
            (r"/analytics/mobile/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)", AnalyticsMobileHandler),
            (r"/analytics/hit/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)", AnalyticsHitHandler),
            (r"/analytics/coordinates/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)", AnalyticsCoordinateHandler),
            (r"/analytics/logs", TailSocketHandler),
            (r"/deployment/([0-9a-zA-Z_\-]+)", DeploymentHandler)
        ]

        tornado.web.Application.__init__(self, handlers, **settings)

        self.gcm = GCM(options.gcm_api_key)
        self.apns = APNSNotificationWrapper(options.apns_certificate, options.apns_sandbox_mode)


        #twitter bots
        self.twitter_bots = {}
        for language in options.twitter_keys:
            self.twitter_bots[language] = twitter.Api(
                consumer_key=options.twitter_keys[language]['consumer_key'],
                consumer_secret=options.twitter_keys[language]['consumer_secret'],
                access_token_key=options.twitter_keys[language]['access_token_key'],
                access_token_secret=options.twitter_keys[language]['access_token_secret']
            )

            if self.twitter_bots[language].VerifyCredentials() is None:
                raise Exception("Twitter bot credentials are wroooong ! ")

        # Have one global connection to the TDT DB across all handlers
        self.db = torndb.Connection(
            host="localhost", database=options.mysql_database,
            user=options.mysql_user, password=options.mysql_password)


    @tornado.gen.engine
    def traffic_differ(self, language, callback):
        #traffic differ with mysql stored events (md5 hash)
        try:
            old = open('%s.json' % language, "rb").read()
            new = requests.get("http://data.beroads.com/IWay/TrafficEvent/%s/all.json" % language).content
            with open('%s.json' % language, "wb") as f:
                f.write(new)
            old = json.loads(old)
            new = json.loads(new)

            t = '{"TrafficEvent":{"item":['
            for i in range(0, len(new['TrafficEvent']['item'])):
                present = False
                for j in range(0, len(old['TrafficEvent']['item'])):
                    if int(new['TrafficEvent']['item'][i]['id']) == int(old['TrafficEvent']['item'][j]['id']):
                        present = True
                if not present:
                    t += json.dumps(new['TrafficEvent']['item'][i]) + ","

            if t[-1] == ",":
                t = t[:-1] + ']}}'
            else:
                t += ']}}'
            callback(json.loads(t))
        except ValueError as e:
            logging.error(e)
            callback(None)


    @tornado.gen.engine
    def notify_subscribers(self, language, events, callback):
        """
        """
        logger = logging.getLogger("notification pusher")
        logger.info("Notifying subscribers from channel %s" % language)

        for subscriber in TrafficSocketHandler.channels[language]:
            for event in events['TrafficEvent']['item']:
                distance = int(haversine(subscriber.coords,
                        {'latitude' : float(event['lat']), 'longitude' : float(event['lng'])}))
                if distance < int(subscriber.area):
                    event['distance'] = distance
                    #PUBLISH
                    message = {
                        "uuid": subscriber.uuid,
                        "code": 3,
                        "data": event
                    }
                    logger.info("Sending update to subscriber %s" % subscriber.uuid)
                    subscriber.write_message(tornado.escape.json_encode(message))


        # Google Cloud Service
        for subscriber in GoogleCloudMessagingHandler.gcm_connections[language]:
            for event in events['TrafficEvent']['item']:
                if 'points' in subscriber:
                    current_point = subscriber['points'][0]
                    for i in range(1, len(subscriber['points'])):
                        #compute distance between a point (the event coordinates) and
                        # a line delimited by two points from the points array
                        next_point = subscriber['points'][i]
                        #first we need to get coordinates in cartesian
                        x = nearest_point_segment(current_point, next_point, subscriber['coords'])
                        distance = haversine(x, subscriber['coords']) < subscriber['area']

                else:
                    #TODO : fix this non sense
                    distance = int(haversine({'latitude' : subscriber['coords']['lat'], 'longitude' : subscriber['coords']['lng']},
                            {'latitude' : float(event['lat']), 'longitude' : float(event['lng'])}))

                if distance < int(subscriber['area']):
                    event['distance'] = distance
                    response = self.gcm.json_request(
                            registration_ids=[subscriber['registration_id']], data=event,
                            collapse_key='uptoyou', delay_while_idle=True, time_to_live=3600
                        )
                    logger.info("Sending update %s to google subscriber %s" % (event, subscriber['registration_id']))
                    # Handling errors
                    if 'errors' in response:
                        for error, reg_ids in response['errors'].items():
                            # Check for errors and act accordingly
                            if error is 'NotRegistered':
                                # Remove reg_ids from database
                                logger.error("Device %s not registered, removing from channel %s"%
                                             (subscriber["registration_id"], language))
                                GoogleCloudMessagingHandler.gcm_connections[language].delete(subscriber)
                    if 'canonical' in response:
                        for reg_id, canonical_id in response['canonical'].items():
                            # Repace reg_id with canonical_id in your database
                            subscriber['registration_id'] = canonical_id


        # Apple APNS

        for subscriber in ApplePushNotificationServerHandler.apns_connections[language]:
            for event in events['TrafficEvent']['item']:
                distance = int(haversine(subscriber['coords'],
                        {'latitude' : float(event['lat']), 'longitude' : float(event['lng'])}))
                if distance < int(subscriber['area']):
                    event['distance'] = distance
                    #PUBLISH
                    message = APNSNotification()
                    alert = APNSAlert()
                    message.tokenHex(subscriber['device_token'])
                    #the entire payload is limited to 256bytes so we put an arbitrary limit on 220 chars for the text
                    alert.body(event['location'].encode('utf-8'))
                    message.alert(alert)
                    message.badge(5)
                    message.sound()
                    self.apns.append(message)
                    logger.info("Sending update to apple subscriber %s" % subscriber['device_token'])
            self.apns.notify()

        # Twitter
        for event in events['TrafficEvent']['item']:

            if int(event['time']) > time.time()-(60*60*2):
                share_url = "http://beroads.com/event/%s"%event['id']
                place_id = None

                auth = OAuth1(
                    options.twitter_keys[language]['consumer_key'],
                    options.twitter_keys[language]['consumer_secret'],
                    options.twitter_keys[language]['access_token_key'],
                    options.twitter_keys[language]['access_token_key']
                )

                payload = {'lat' : event['lat'], 'long' : event['lng']}
                r = requests.get('https://api.twitter.com/1.1/geo/search.json', params=payload, auth=auth)

                if r.status_code==200:
                    result = json.loads(r.content)
                    if len(result['result']['places']):
                        place_id = result['result']['places'][0]['id']

                status = "%s ... %s"%(
                    event['location'][0:(140-len(share_url)-4)], share_url)

                logger.info("Publishing status : %s on Twitter..."%status)

                self.twitter_bots[language].PostUpdate(status=status,
                    latitude=event['lat'],
                    longitude=event['lng'],
                    place_id=place_id,
                    display_coordinates=True
                )

        callback(True)

    @tornado.gen.engine
    def load_traffic(self):
        """

        """
        logger = logging.getLogger("traffic loader")
        try:
            languages = ['nl', 'fr', 'de', 'en']
            for language in languages:
                logger.info("Fetching %s traffic ..."%language)
                new_events = yield tornado.gen.Task(self.traffic_differ, language)
                if new_events is not None:
                    published = yield tornado.gen.Task(self.notify_subscribers, language, new_events)
        except Exception as e:
            logger.exception(e)


class TrafficSocketHandler(tornado.websocket.WebSocketHandler):
    """

    """
    logger = logging.getLogger("websocket handler")
    channels = {'fr': [], 'nl': [], 'de': [], 'en': []}

    def allow_draft76(self):
        # for iOS 5.0 Safari
        return True

    def open(self):
        self.logger.info("Websocket connection from %s" % self.ws_connection)
        self.uuid = str(uuid.uuid4())
        ack = {
            "uuid": self.uuid,
            "code": 2
        }
        self.write_message(tornado.escape.json_encode(ack))

    def on_close(self):
        self.channels[self.language].remove(self)

    @classmethod
    def publish(cls, channel, message):
        """
            Publish message to all subscribers on channel.
        """
        for subscriber in cls.channels[channel]:
            subscriber.write_message(tornado.escape.json_encode(message))

    @classmethod
    def test_message(cls, message):
        """
            Verify a subscribe/update message for wrong/missing values.
        """
        if (message["coords"] == None):
            raise AttributeError
        else:
            if (message["coords"]["latitude"] == None or
                message["coords"]["longitude"] == None):
                raise AttributeError
            else:
                if (message["coords"]["latitude"] > 90
                    or message["coords"]["latitude"] < -90):
                    raise ValueError
                if (message["coords"]["longitude"] > 180
                    or message["coords"]["longitude"] < -180):
                    raise ValueError

        if message["area"] == None:
            raise AttributeError
        else:
            if message["area"] < 0:
                raise ValueError

        if message["language"] == None:
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

        self.logger.info("got message %r", message)

        try:
            parsed = tornado.escape.json_decode(message)
            #SUBSCRIBE OR UPDATE
            if int(parsed['code']) == 1:
                TrafficSocketHandler.test_message(parsed)

                self.uuid = str(uuid.uuid4())
                self.language = parsed['language']
                self.coords = parsed['coords']
                self.area = parsed["area"]

                self.channels[self.language].append(self)
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
                for subscriber in self.channels[self.config['language']]:
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
                self.logger.info("ACK received from subscriber " + self.ws_connection.uuid.value)

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

tailed_file = open('beroads.log')
tailed_file.seek(os.path.getsize('beroads.log'))

class TailSocketHandler(tornado.websocket.WebSocketHandler):
    """
        Websocket handler that register a tailed file and send new line to the connected clients.
    """
    ws_connections = []


    def allow_draft76(self):
        # for iOS 5.0 Safari
        return True

    def open(self):
        self.ws_connections.append(self.ws_connection)

    def on_close(self):
        self.ws_connections.remove(self.ws_connection)

    @classmethod
    def check_file(self):
        where = tailed_file.tell()
        line = tailed_file.readline()
        if not line:
            tailed_file.seek(where)
        else:
            try:
                for subscriber in self.ws_connections:
                    subscriber.write_message(line)
            except StreamClosedError:
                self.ws_connections.remove(subscriber)


class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    @property
    def gcm(self):
        return self.application.gcm

    @property
    def apns(self):
        return self.application.apns

    def auth(self, username, password):
        authenticated = self.db.query("SELECT * FROM user WHERE username=%s AND password = UNHEX(%s)",
            username,
            hashlib.sha1(password).hexdigest())
        return authenticated


class GoogleCloudMessagingHandler(BaseHandler):

    logger = logging.getLogger("GCM handler")
    gcm_connections = {'fr': [], 'nl': [], 'de': [], 'en': []}


    def post(self, *args, **kwargs):
        try:
            self.logger.info("Request received from android device : " + self.request.body)
            data = tornado.escape.json_decode(str(self.request.body))
            if(data['registration_id'] is None or data['registration_id'] == ""):
                raise AttributeError("registration_id is not set")

            if(data['language'] is None):
                raise AttributeError("language is not set")
            if(data['language'] not in ['fr', 'nl', 'en', 'de']):
                raise AttributeError("language is not valid")

            if data['area'] is None or data['area'] == "":
                raise AttributeError("area is not set")

            if data['area'] < 0:
                raise ValueError("area must be a positive value")

            if data['coords'] is None or data['coords'] == "":
                raise AttributeError("coords is not set")

            if (data["coords"]["lat"] == None or
                data["coords"]["lng"] == None):
                raise AttributeError('latitude is not set')
            else:
                if (data["coords"]["lat"] > 90
                    or data["coords"]["lat"] < -90):
                    raise ValueError("latitude is not valid")
                if (data["coords"]["lng"] > 180
                    or data["coords"]["lng"] < -180):
                    raise ValueError("longitude is not valid")

            present = False
            for subscriber in self.gcm_connections[data['language']]:
                if subscriber['registration_id'] == data['registration_id']:
                    subscriber = data
                    present = True

            if not present:
                data['timestamp'] = time.time()
                self.gcm_connections[data['language']].append(data)

            self.set_status(200)

        except Exception as e:
            self.logger.error(e)
            self.send_error(500)


class AppleSendNotificationHandler(BaseHandler):
    def get(self, *args, **kwargs):
        if self.get_argument("device_token") is not None and self.get_argument("message") is not None:
            message = APNSNotification()
            alert = APNSAlert()
            alert.body(str(self.get_argument("message")))
            message.tokenHex(self.get_argument("device_token"))
            #the entire payload is limited to 256bytes so we put an arbitrary limit on 220 chars for the text
            message.alert(alert)
            message.badge(1)
            message.sound()
            self.apns.append(message)
            self.apns.notify()
        else:
            self.send_error(404)

class WebsocketSendNotificationHandler(BaseHandler):

    def get(self, *args, **kwargs):
        if self.get_argument("uuid") is not None and self.get_argument("message") is not None:
            for subscriber in TrafficSocketHandler.channels[language]:
                if subscriber.uuid == self.get_argument("uuid"):
                    message = {
                        "uuid": subscriber.uuid,
                        "code": 3,
                        "data": self.get_argument("message")
                    }
                    subscriber.write_message(tornado.escape.json_encode(message))
        else:
            self.send_error(404)


class ApplePushNotificationServerHandler(BaseHandler):

    logger = logging.getLogger("APNS handler")
    apns_connections = {'fr': [], 'nl': [], 'de': [], 'en': []}
    SUPPORTED_METHODS = ("POST")

    @classmethod
    def feedback(cls):
        logger = logging.getLogger("APNS feedback")
        feedback = APNSFeedbackWrapper(options.apns_certificate, True)
        feedback.receive()
        for x, y in feedback:
            logger.info("Device token %s unavailable since %s"%(str(y), x.strftime("%m %d %Y %H:%M:%S")))
            for channel in cls.apns_connections:
                for subscriber in channel:
                    if subscriber['device_token'] == y:
                        channel.remove(subscriber)

    def post(self, *args, **kwargs):
        try:
            self.logger.info("Request received from iDevice : " + self.request.body)
            data = tornado.escape.json_decode(str(self.request.body))
            if(data['device_token'] is None or data['device_token'] == ""):
                raise AttributeError("device_token is not set")

            if(data['language'] is None):
                raise AttributeError("language is not set")
            if(data['language'] not in ['fr', 'nl', 'en', 'de']):
                raise AttributeError("language is not valid")

            if data['area'] is None or data['area'] == "":
                raise AttributeError("area is not set")

            if data['area'] < 0:
                raise ValueError("area must be a positive value")

            if data['coords'] is None or data['coords'] == "":
                raise AttributeError("coords is not set")

            if (data["coords"]["latitude"] == None or
                data["coords"]["longitude"] == None):
                raise AttributeError('latitude is not set')
            else:
                if (float(data["coords"]["latitude"]) > 90
                    or float(data["coords"]["latitude"]) < -90):
                    raise ValueError("latitude is not valid")
                else:
                    data['coords']['latitude'] = float(data['coords']['latitude'])
                if (float(data["coords"]["longitude"]) > 180
                    or float(data["coords"]["longitude"]) < -180):
                    raise ValueError("longitude is not valid")
                else:
                    data['coords']['longitude'] = float(data['coords']['longitude'])

            present = False
            for subscriber in self.apns_connections[data['language']]:
                if subscriber['device_token'] == data['device_token']:
                    subscriber = data
                    present = True

            if not present:
                data['timestamp'] = time.time()
                self.apns_connections[data['language']].append(data)

            self.set_status(200)

        except Exception as e:
            self.logger.error(e)
            self.send_error(500)


@require_basic_auth
class DeploymentHandler(BaseHandler):
    """
        Request handler for admin users that allows specific deployment commands.
    """

    def get(self, target, basicauth_user, basicauth_pass):
        if self.auth(basicauth_user, basicauth_pass):
            try:
                message = ""
                if target == 'mobile':
                    logging.info("Deploying mobile application")
                    message = subprocess.check_output('cd `pwd`/Mobile && git pull')
                    message += subprocess.check_output("/usr/bin/Sencha/Cmd/3.1.0.256/sencha app build %s" %
                                                       self.get_argument('deployment_type', 'testing'))
                elif target == 'tdt':
                    logging.info("Deploying TDT server")
                    message = subprocess.check_output('cd `pwd`/The-DataTank && git pull')
                elif target == 'website':
                    logging.info("Deploying website")
                    message = subprocess.check_output('cd `pwd`/Home && git pull')
                else:
                    self.write_error(404)
                logging.info(message)
                data = {
                    "success": 1,
                    "message": message
                }
            except Exception as e:
                data = {
                    "success": 0,
                    "message": str(e)
                }

            self.set_header("Content-Type", "text/json; charset=UTF-8")
            self.write(tornado.escape.json_encode(data))
        else:
            self.write_error(403)


@require_basic_auth
class DashboardHandler(BaseHandler):
    def get(self, basicauth_user, basicauth_pass):
        if self.auth(basicauth_user, basicauth_pass):
            self.set_header("Content-Type", "text/html; charset=UTF-8")

            sources = [
                    {
                    'name': 'Centre Perex',
                    'url': 'http://trafiroutes.wallonie.be',
                    'status': 0
                },
                    {
                    'name': 'Mobiris',
                    'url': 'http://www.bruxellesmobilite.irisnet.be',
                    'status': 0
                },
                    {
                    'name': 'Verkeers Centrum',
                    'url': 'http://www.verkeerscentrum.be',
                    'status': 0
                },
                    {
                    'name': 'Police fédérale',
                    'url': 'http://www.fedpol.be',
                    'status': 0
                }
            ]

            for source in sources:
                try:
                    start = time.time()
                    r = requests.get(source['url'])
                    end = time.time()
                    source['status'] = r.status_code
                    source['response_time'] = "%.2f" % (end - start)
                except requests.ConnectionError:
                    source['status'] = 0
            packages = dict()
            for p_row in self.db.query("SELECT id, package_name FROM package"):
                packages[str(p_row['package_name'])] = []
                for r_row in self.db.query("SELECT resource_name FROM resource WHERE package_id = %s", p_row['id']):
                    packages[p_row['package_name']].append(str(r_row['resource_name']))

            traffic_feed_channels = TrafficSocketHandler.channels
            events_count = []
            for feed in traffic_feed_channels:
                events_count.append(len(json.loads(open("%s.json" % feed).read())['TrafficEvent']['item']))

            google_subscribers = GoogleCloudMessagingHandler.gcm_connections
            apple_subscribers = ApplePushNotificationServerHandler.apns_connections
            web_subscribers = TrafficSocketHandler.channels

            self.render("templates/index.html", username=basicauth_user, sources=sources,
                traffic_feed_channels=traffic_feed_channels, google_subscribers=google_subscribers,
                events_count=events_count, apple_subscribers=apple_subscribers, web_subscribers=web_subscribers,
                packages=packages)
        else:
            self.send_error(403)

@require_basic_auth
class AnalyticsSubscribersHandler(BaseHandler):

    subscribers_types = ['web', 'apple', 'google']
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, subscriber_type, basicauth_user, basicauth_pass):
        """
            Request all user agents for specific TDT package and resource between start_date and end_date if provided.
            Compute per OS requests percentage and send them back.
        """

        if self.auth(basicauth_user, basicauth_pass):
            if subscriber_type in self.subscribers_types:
                if subscriber_type == "web":
                    data = {}
                    for channel in TrafficSocketHandler.channels:
                        data[channel] = []
                        for subscriber in TrafficSocketHandler.channels[channel]:
                            data[channel].append({"uuid" : subscriber.uuid, "coords" : subscriber.coords})
                elif subscriber_type == "google":
                    data = GoogleCloudMessagingHandler.gcm_connections
                elif subscriber_type == "apple":
                    data = ApplePushNotificationServerHandler.apns_connections

                self.set_header("Content-Type", "text/json; charset=UTF-8")
                self.write(tornado.escape.json_encode(data))
                self.finish()
            else:
                self.write_error(404)
        else:
            self.write_error(403)

@require_basic_auth
class AnalyticsOSHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        """
            Request all user agents for specific TDT package and resource between start_date and end_date if provided.
            Compute per OS requests percentage and send them back.
        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())

            package_present = self.db.query(options.package_query, str(package))
            resource_present = self.db.query("SELECT * FROM resource WHERE resource_name = %s", str(resource))

            if (package == 'all' or package_present) and (resource == 'all' or resource_present):
                if package == "all":
                    package = "%"
                if resource == "all":
                    resource = "%"

                data = yield tornado.gen.Task(self.parse_user_agents, package, resource, start_date, end_date)
                self.set_header("Content-Type", "text/json; charset=UTF-8")
                self.write(tornado.escape.json_encode(data))
                self.finish()

            else:
                self.write_error(404)
        else:
            self.write_error(403)

    def parse_user_agents(self, package, resource, start_date, end_date, callback):
        rows = self.db.query("""
               SELECT COUNT(*) as total,
              CASE
              WHEN LOWER(user_agent) LIKE "%%windows nt 6.2%%" THEN "Windows 8"
              WHEN LOWER(user_agent) LIKE "%%windows nt 6.1%%" THEN "Windows 7"
              WHEN LOWER(user_agent) LIKE "%%windows nt 6.0%%" THEN "Windows Vista"
              WHEN LOWER(user_agent) LIKE "%%windows nt 5.2%%" THEN "Windows Server 2003/XP x64"
              WHEN LOWER(user_agent) LIKE "%%windows nt 5.1%%" THEN "Windows XP"
              WHEN LOWER(user_agent) LIKE "%%windows nt 5.0%%" THEN "Windows 2000"
              WHEN LOWER(user_agent) LIKE "%%windows me%%" THEN "Windows ME"
              WHEN LOWER(user_agent) LIKE "%%win98%%" THEN "Windows 98"
              WHEN LOWER(user_agent) LIKE "%%win95%%" THEN "Windows 95"
              WHEN LOWER(user_agent) LIKE "%%win16%%" THEN "Windows 3.1"
              WHEN LOWER(user_agent) LIKE "%%macintosh%%" THEN "Mac OSX"
              WHEN LOWER(user_agent) LIKE "%%mac_powerpc%%" THEN "Mac OS 9"
              WHEN LOWER(user_agent) LIKE "%%linux%%" THEN "Linux"
              WHEN LOWER(user_agent) LIKE "%%iphone%%" THEN "iOS"
              WHEN LOWER(user_agent) LIKE "%%ipod%%" THEN "iOS"
              WHEN LOWER(user_agent) LIKE "%%ipad%%" THEN "iOS"
              WHEN LOWER(user_agent) LIKE "%%android%%" THEN "Android"
              WHEN LOWER(user_agent) LIKE "%%blackberry%%" THEN "Blackberry"
              WHEN LOWER(user_agent) LIKE "%%iemobile%%" THEN "Windows Phone"
              ELSE "Other"
              END as os
              FROM requests
              WHERE (LOWER(user_agent) LIKE "%%windows nt 6.2%%"
              OR LOWER(user_agent) LIKE "%%windows nt 6.1%%"
              OR LOWER(user_agent) LIKE "%%windows nt 6.0%%"
              OR LOWER(user_agent) LIKE "%%windows nt 5.2%%"
              OR LOWER(user_agent) LIKE "%%windows nt 5.1%%"
              OR LOWER(user_agent) LIKE "%%windows nt 5.0%%"
              OR LOWER(user_agent) LIKE "%%windows me%%"
              OR LOWER(user_agent) LIKE "%%win98%%"
              OR LOWER(user_agent) LIKE "%%win95%%"
              OR LOWER(user_agent) LIKE "%%win16%%"
              OR LOWER(user_agent) LIKE "%%macintosh%%"
              OR LOWER(user_agent) LIKE "%%mac_powerpc%%"
              OR LOWER(user_agent) LIKE "%%linux%%"
              OR LOWER(user_agent) LIKE "%%iphone%%"
              OR LOWER(user_agent) LIKE "%%ipod%%"
              OR LOWER(user_agent) LIKE "%%ipad%%"
              OR LOWER(user_agent) LIKE "%%android%%"
              OR LOWER(user_agent) LIKE "%%blackberry%%"
              OR LOWER(user_agent) LIKE "%%iemobile%%")
              AND time >= %s AND time <= %s AND package LIKE %s AND resource LIKE %s GROUP BY os ORDER BY time DESC""",
            int(start_date), int(end_date), str(package), str(resource))
        data = []
        try:
            for row in rows:
                data.append({
                    'name': row['os'],
                    'total': int(row['total'])
                })
            callback(data)
        except Exception, e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsBrowserHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        """
            Request all user agents for specific TDT package and resource between start_date and end_date if provided.
            Compute per browser requests percentage and send them back.
        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = self.db.query("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = self.db.query("SELECT * FROM resource WHERE resource_name = %s", str(resource))

            if (package == 'all' or package_present) and (resource == 'all' or resource_present):
                if package == "all":
                    package = "%"
                if resource == "all":
                    resource = "%"

                data = yield tornado.gen.Task(self.parse_user_agents, package, resource, start_date, end_date)
                self.set_header("Content-Type", "text/json; charset=UTF-8")
                self.write(tornado.escape.json_encode(data))
                self.finish()
            else:
                self.write_error(404)
        else:
            self.write_error(403)

    def parse_user_agents(self, package, resource, start_date, end_date, callback):
        rows = self.db.query("""
                SELECT COUNT(*) as total,
                CASE
                  WHEN LOWER(user_agent) LIKE "%%firefox/%%" THEN "Firefox"
                  WHEN LOWER(user_agent) LIKE "%%chrome/%%" THEN "Chrome"
                  WHEN LOWER(user_agent) LIKE "%%chromium/%%" THEN "Chromium"
                  WHEN LOWER(user_agent) LIKE "%%safari/%%" THEN "Safari"
                  WHEN LOWER(user_agent) LIKE "%%opera/%%" THEN "Opera"
                  WHEN LOWER(user_agent) LIKE "%%;msie%%" THEN "Internet Explorer"
                  ELSE "Other"
                  END as browser
                  FROM requests
                  WHERE (LOWER(user_agent) LIKE "%%firefox/%%"
                  OR LOWER(user_agent) LIKE "%%chrome/%%"
                  OR LOWER(user_agent) LIKE "%%chromium/%%"
                  OR LOWER(user_agent) LIKE "%%safari/%%"
                  OR LOWER(user_agent) LIKE "%%opera/%%"
                  OR LOWER(user_agent) LIKE "%%;msie%%")
                  AND time >= %s AND time <= %s AND package LIKE %s AND resource LIKE %s
                  GROUP BY browser
                  ORDER BY time DESC""",
            int(start_date), int(end_date), package, resource)

        data = []
        try:
            for row in rows:
                data.append({
                    'name': row['browser'],
                    'total': int(row['total'])
                })
            callback(data)
        except Exception, e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsCoordinateHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        """

        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = self.db.query("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = self.db.query("SELECT * FROM resource WHERE resource_name = %s", str(resource))

            if (package == 'all' or package_present) and (resource == 'all' or resource_present):
                if package == "all":
                    package = "%"
                if resource == "all":
                    resource = "%"

                data = yield tornado.gen.Task(self.parse_coordinates, package, resource, start_date, end_date)
                self.set_header("Content-Type", "text/json; charset=UTF-8")
                self.write(tornado.escape.json_encode(data))
                self.finish()

            else:
                self.write_error(404)
        else:
            self.write_error(403)

    def parse_coordinates(self, package, resource, start_date, end_date, callback):
        rows = self.db.query("""
                SELECT
                    SUBSTRING_INDEX(
                        SUBSTRING_INDEX(
                            SUBSTRING_INDEX(
                                SUBSTRING_INDEX(
                                    SUBSTRING_INDEX(
                                        SUBSTRING_INDEX(
                                            SUBSTRING_INDEX(`url_request`, 'from=',-1), '&area=', 1
                                        ), 'region=', 1
                                    ), '&group=', 1
                                ), '&callback=', 1
                            ), '&lang=', 1
                        ),'&', 1
                    )
                    AS url
                    FROM
                        requests
                    WHERE `url_request` LIKE "%%from=%%&area=%%"
                    AND time >= %s AND time <= %s AND package LIKE %s AND
                    resource LIKE %s ORDER BY time DESC
                    """, int(start_date), int(end_date), package, resource)

        data = []
        try:
            for row in rows:
                try:
                    coords = row['url'].split(',')
                    data.append({
                        'lat': float(coords[0]),
                        'lng': float(coords[1]),
                        'count': 1

                    })
                except ValueError:
                    continue
            callback(data)
        except Exception, e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsHitHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, package, resource, frequency, basicauth_user, basicauth_pass):
        """

        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = self.db.query("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = self.db.query("SELECT * FROM resource WHERE resource_name = %s", str(resource))

            if (package == 'all' or package_present) and (resource == 'all' or resource_present):
                if package == "all":
                    package = "%"
                if resource == "all":
                    resource = "%"

                data = yield tornado.gen.Task(self.parse_hits, package, resource, start_date, end_date, frequency)
                self.set_header("Content-Type", "text/json; charset=UTF-8")
                self.write(tornado.escape.json_encode(data))
                self.finish()
            else:
                self.write_error(404)
        else:
            self.write_error(403)


    def parse_hits(self, package, resource, start_date, end_date, frequency, callback):
        d = {'daily': 'day', 'weekly': 'week', 'monthly': 'month', 'yearly': 'year'}

        rows = self.db.query("""
                        SELECT
                            COUNT(*) as hits,
                            FROM_UNIXTIME(time, \"%%j\") as day,
                            FROM_UNIXTIME(time, \"%%u\") as week,
                            FROM_UNIXTIME(time, \"%%m\") as month,
                            FROM_UNIXTIME(time, \"%%Y\") as year,
                            FROM_UNIXTIME(time, \"%%d-%%m-%%Y\") as name
                            FROM requests
                            WHERE time >= %s AND time <= %s AND package LIKE %s AND
                    resource LIKE %s AND (LOWER(`user_agent`) NOT LIKE "%%python%%" AND LOWER(`user_agent`) NOT LIKE "%%wget%%")
                    GROUP BY """ + d[frequency] + """ ORDER BY time ASC
                    """, int(start_date), int(end_date), str(package), str(resource))

        data = []
        try:
            for row in rows:
                data.append({
                    'name': row['name'],
                    'total': int(row['hits'])
                })
            callback(data)
        except Exception, e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsLanguageHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = self.db.query("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = self.db.query("SELECT * FROM resource WHERE resource_name = %s", str(resource))

            if (package == 'all' or package_present) and (resource == 'all' or resource_present):
                if package == "all":
                    package = "%"
                if resource == "all":
                    resource = "%"

                data = yield tornado.gen.Task(self.parse_languages, package, resource, start_date, end_date)
                self.set_header("Content-Type", "text/json; charset=UTF-8")
                self.write(tornado.escape.json_encode(data))
                self.finish()
            else:
                self.write_error(404)
        else:
            self.write_error(403)

    def parse_languages(self, package, resource, start_date, end_date, callback):
        rows = self.db.query("""
            SELECT
                CASE
                    WHEN LOWER(`url_request`) LIKE "%%/fr/%%" THEN "French"
                    WHEN LOWER(`url_request`) LIKE "%%/nl/%%" THEN "Dutch"
                    WHEN LOWER(`url_request`) LIKE "%%/en/%%" THEN "English"
                    WHEN LOWER(`url_request`) LIKE "%%/de/%%" THEN "German"
                    ELSE "Other"
                END AS language,
                COUNT(id) AS hits,
                (COUNT(id)*100 /
                    (SELECT COUNT(*)
                        FROM requests
                        WHERE (LOWER(`user_agent`) NOT LIKE "%%python%%" AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
                    )
                    AND (
                        LOWER(`url_request`) LIKE "%%/fr/%%"
                        OR LOWER(`url_request`) LIKE "%%/nl/%%"
                        OR LOWER(`url_request`) LIKE "%%/de/%%"
                        OR LOWER(`url_request`) LIKE "%%/en/%%"))) AS percentage
                FROM
                    requests
                WHERE
                    (LOWER(`user_agent`) NOT LIKE "%%python%%" AND LOWER(`user_agent`) NOT LIKE "%%wget%%")
                    AND (
                        LOWER(`url_request`) like "%%/fr/%%"
                        OR LOWER(`url_request`) like "%%/nl/%%"
                        OR LOWER(`url_request`) like "%%/de/%%"
                        OR LOWER(`url_request`) like "%%/en/%%")
                AND time >= %s AND time <= %s AND package LIKE %s AND
                    resource LIKE %s GROUP BY language ORDER BY hits DESC
                    """, int(start_date), int(end_date), package, resource)

        data = []
        try:
            for row in rows:
                data.append({
                    'name': row['language'],
                    'total': int(row['hits'])
                })
            callback(data)
        except Exception, e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsMobileHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        """

        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = self.db.query("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = self.db.query("SELECT * FROM resource WHERE resource_name = %s", str(resource))

            if (package == 'all' or package_present) and (resource == 'all' or resource_present):
                if package == "all":
                    package = "%"
                if resource == "all":
                    resource = "%"

                data = yield tornado.gen.Task(self.parse_user_agents, package, resource, start_date, end_date)
                self.set_header("Content-Type", "text/json; charset=UTF-8")
                self.write(tornado.escape.json_encode(data))
                self.finish()
            else:
                self.write_error(404)
        else:
            self.write_error(403)

    def parse_user_agents(self, package, resource, start_date, end_date, callback):
        rows = self.db.query("""SELECT COUNT(*) as total,
            CASE
            WHEN user_agent LIKE "%%iPhone%%" THEN "iPhone"
            WHEN user_agent LIKE "%%iPod%%" THEN "iPod"
            WHEN user_agent LIKE "%%iPad%%" THEN "iPad"
            WHEN user_agent LIKE "%%Android%%" THEN "Android"
            WHEN user_agent LIKE "%%BlackBerry%%" THEN "BlackBerry"
            WHEN user_agent LIKE "%%IEMobile%%" THEN "IEMobile"
            WHEN user_agent LIKE "%%Kindle%%" THEN "Kindle"
            WHEN user_agent LIKE "%%NetFront%%" THEN "NetFront"
            WHEN user_agent LIKE "%%Silk-Accelerated%%" THEN "Silk-Accelerated"
            WHEN user_agent LIKE "%%hpwOS%%" THEN "WebOS"
            WHEN user_agent LIKE "%%webOS%%" THEN "webOS"
            WHEN user_agent LIKE "%%Minimo%%" THEN "Minimo"
            WHEN user_agent LIKE "%%Fennec%%" THEN "Fennec"
            WHEN user_agent LIKE "%%Opera Mobi%%" THEN "Opera Mobile"
            WHEN user_agent LIKE "%%Opera Mini%%" THEN "Opera Mini"
            WHEN user_agent LIKE "%%Blazer%%" THEN "Blazer"
            WHEN user_agent LIKE "%%Dolfin%%" THEN "Dolfin"
            WHEN user_agent LIKE "%%Dolphin%%" THEN "Dolphin"
            WHEN user_agent LIKE "%%Skyfire%%" THEN "Skyfire"
            WHEN user_agent LIKE "%%Zune%%" THEN "Zune"
            ELSE "Other"
            END as browser
            FROM requests
            WHERE time >= %s AND time <= %s AND package LIKE %s
            AND resource LIKE %s
            AND (user_agent LIKE "%%iPhone%%"
            OR user_agent LIKE "%%iPod%%"
            OR user_agent LIKE "%%iPad%%"
            OR user_agent LIKE "%%Android%%"
            OR user_agent LIKE "%%BlackBerry%%"
            OR user_agent LIKE "%%IEMobile%%"
            OR user_agent LIKE "%%Kindle%%"
            OR user_agent LIKE "%%NetFront%%"
            OR user_agent LIKE "%%Silk-Accelerated%%"
            OR user_agent LIKE "%%hpwOS%%"
            OR user_agent LIKE "%%webOS%%"
            OR user_agent LIKE "%%Minimo%%"
            OR user_agent LIKE "%%Fennec%%"
            OR user_agent LIKE "%%Opera Mobi%%"
            OR user_agent LIKE "%%Opera Mini%%"
            OR user_agent LIKE "%%Blazer%%"
            OR user_agent LIKE "%%Dolfin%%"
            OR user_agent LIKE "%%Dolphin%%"
            OR user_agent LIKE "%%Skyfire%%"
            OR user_agent LIKE "%%Zune%%")
            AND (LOWER(`user_agent`) NOT LIKE "%%python%%" AND LOWER(`user_agent`) NOT LIKE "%%wget%%")
            GROUP BY browser ORDER BY time DESC""", int(start_date), int(end_date), package, resource)

        data = []
        try:
            for row in rows:
                data.append({
                    'name': row['browser'],
                    'total': int(row['total'])
                })
            callback(data)
        except Exception, e:
            logging.error(e)
            callback(data)
        return


if __name__ == "__main__":

    app = Application()
    app.listen(options.port)
    logging.info("Starting BeRoads webserver on address %s:%s" % (options.ip, options.port))
    main_loop = tornado.ioloop.IOLoop.instance()

    #register periodic callbacks to fetch webcams images and fech traffic from data.beroads.com and notify
    #websockets subscribers.
    tornado.ioloop.PeriodicCallback(app.load_traffic, options.traffic_fetch_frequency, io_loop=main_loop).start()

    #start a periodic callback to tail our log file and send new line to websocket client
    tailed_callback = tornado.ioloop.PeriodicCallback(TailSocketHandler.check_file, 500)
    tailed_callback.start()

    feedback_callback = tornado.ioloop.PeriodicCallback(ApplePushNotificationServerHandler.feedback, 3600000)
    feedback_callback.start()

    main_loop.start()


