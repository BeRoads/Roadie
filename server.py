# -*- coding: utf-8 -*-
__author__ = 'quentinkaiser'
import memcache
import sys
import tornado.escape
import tornado.ioloop
from tornado.options import options, define
import tornado.web
import tornado.websocket
import tornado.gen
from tornado.iostream import StreamClosedError

from optparse import OptionParser
import logging
import os
import requests
import torndb
import time
import base64
import hashlib
import subprocess
import numpy as np
from math import radians, cos, sin, asin, sqrt, atan2
import uuid

from gcm import *
from apns_clerk import *
import configparser

def require_basic_auth(handler_class):

    def wrap_execute(handler_execute):

        def require_basic_auth(handler, kwargs):
            auth_header = handler.request.headers.get('Authorization')
            if auth_header is None or not auth_header.startswith('Basic '):

                handler.set_status(401)
                handler.set_header('WWW-Authenticate', 'Basic realm=Restricted')
                handler._transforms = []
                handler.finish()
                return False

            auth_decoded = base64.decodestring(auth_header[6:])
            username, password = auth_decoded.split(':', 2)
            kwargs['basicauth_user'], kwargs['basicauth_pass'] = username, password
            return True

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
    lon1, lat1, lon2, lat2 = map(radians, [a['longitude'], a['latitude'], b['longitude'], b['latitude']])
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    km = R * c
    return km


def to_cartesian(latitude, longitude):
    """

    """
    x = R * cos(latitude) * cos(longitude)
    y = R * cos(latitude) * sin(longitude)
    z = R * sin(latitude)
    return {'x': x, 'y': y, 'z': z}


def from_cartesian(a):
    """
        a is a cartesian coordinates array [x, y, z]
    """
    latitude = asin(a['z'] / R)
    longitude = atan2(a['y'], a['x'])
    return {'latitude': latitude, 'longitude': longitude}


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
    return abs(haversine(a, b) - haversine(a, t) - haversine(b, t)) < PRECISION


def nearest_point_segment(a, b, c):
    """

    """
    t = nearest_point_great_circle(a, b, c)
    if on_segment(a, b, t):
        return t
    return a if haversine(a, c) < haversine(b, c) else c



class Application(tornado.web.Application):
    def __init__(self, config):


        settings = dict(
            cookie_secret="5725af95ef74805b753cd3689bb3393681e02ce6",
            static_path="%s/static"%os.path.dirname(os.path.abspath(__file__)) ,
            xsrf_cookies=False,
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
            (r"/analytics/device/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)", AnalyticsDeviceHandler),
            (r"/analytics/hit/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)", AnalyticsHitHandler),
            (r"/analytics/notification/([0-9a-zA-Z_\-]+)", AnalyticsNotificationsHandler),
            (r"/analytics/coordinates/([0-9a-zA-Z_\-]+)/([0-9a-zA-Z_\-]+)", AnalyticsCoordinateHandler),
            (r"/deployment/([0-9a-zA-Z_\-]+)", DeploymentHandler)
        ]

        tornado.web.Application.__init__(self, handlers, **settings)

        self.config = config

        self.last_insert_time = int(time.time())
        self.gcm = GCM(self.config['push']['gcm_api_key'])

        session = Session()
        con = session.get_connection("push_production", cert_file='%s/%s'%(os.path.dirname(os.path.abspath(__file__)) , self.config['push']['apns_certificate']),
            key_file='%s/%s'%(os.path.dirname(os.path.abspath(__file__)) , self.config['push']['apns_key']),
            passphrase=str(self.config['push']['apns_passphrase']))
        self.apns = APNs(con)
        # Have one global connection to the TDT DB across all handlers
        self.db = torndb.Connection(
            host=self.config['mysql']['host'],
            database=self.config['mysql']['database'],
            user=self.config['mysql']['username'],
            password=self.config['mysql']['password']
        )

        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("webcams")
        self.logger.setLevel(logging.INFO)

        default_file = logging.FileHandler("%s-default.log" % (str(self.config['server']['log_filename'])), delay=True)
        default_file.setLevel(logging.INFO)
        default_file.setFormatter(formatter)
        self.logger.addHandler(default_file)
        default_file.close()

        error_file = logging.FileHandler("%s-error.log" % (str(self.config['server']['log_filename'])), delay=True)
        error_file.setLevel(logging.ERROR)
        error_file.setFormatter(formatter)
        self.logger.addHandler(error_file)
        error_file.close()



        self.cache = memcache.Client(
            ['%s:%d' % (
                self.config['memcached']['ip'],
                int(self.config['memcached']['port'])
                )],
            debug=True
        )

        for contype in ['apns', 'gcm', 'web']:
            for language in ['fr', 'nl', 'de', 'en']:
                subscribers = self.cache.get(str('subscribers.%s.%s' % (contype, language)))
                if subscribers is None:
                    self.cache.set(str('subscribers.%s.%s' % (contype, language)), [])


    def log_notification(self, notif):
        """
            Logs a notification into our mysql database
        """
        self.db.execute("INSERT INTO notification_logs (uuid, type, size, time) VALUES "
                        "(\"%s\", \"%s\", %d, %d)" %
                        (notif['uuid'], notif['type'], notif['size'], notif['time']))
        return

    @tornado.gen.engine
    def traffic_differ(self, language, callback):
        #traffic differ with mysql stored events (md5 hash)
        try:
            rows = self.db.query("SELECT * FROM trafic WHERE language = '%s' AND insert_time > %d" %
                                 (language, self.last_insert_time))
            callback(rows)
        except Exception as e:
            logging.error(e)
            callback(None)


    @tornado.gen.engine
    def notify_subscribers(self, language, events, callback):
        """
        """
        self.logger.info("Notifying subscribers from channel %s" % language)

        
	for subscriber in self.cache.get(str('subscribers.web.%s' % language)) or []:
            for event in events:
                distance = int(haversine(subscriber.coords,
                        {'latitude': float(event['lat']), 'longitude': float(event['lng'])}))
                if distance < int(subscriber.area):
                    event['distance'] = distance
                    #PUBLISH
                    message = {
                        "uuid": subscriber.uuid,
                        "code": 3,
                        "data": event
                    }
                    self.logger.info("Sending update to subscriber %s" % subscriber.uuid)
                    notif = {"uuid": subscriber.uuid, "type": "web", "size": len(str(event)), "time": int(time.time())}
                    subscriber.write_message(tornado.escape.json_encode(message))
                    self.log_notification(notif)


        # Google Cloud Service
        subscribers = self.cache.get(str('subscribers.gcm.%s' % language))
        for subscriber in subscribers:
            for event in events:
                distance = sys.maxint
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
                    distance = int(
                        haversine({'latitude': subscriber['coords']['lat'], 'longitude': subscriber['coords']['lng']},
                                {'latitude': float(event['lat']), 'longitude': float(event['lng'])}))

                if distance < int(subscriber['area']):
                    event['distance'] = distance
                    response = self.gcm.json_request(
                        registration_ids=[subscriber['registration_id']], data=event,
                        collapse_key='beroads', delay_while_idle=True, time_to_live=3600
                    )
                    self.logger.info("Sending update %s to google subscriber %s" % (event, subscriber['registration_id']))
                    # Handling errors
                    if 'errors' in response:
                        for error, reg_ids in response['errors'].items():
                            # Check for errors and act accordingly
                            if error is 'NotRegistered':
                                # Remove reg_ids from database
                                self.logger.error("Device %s not registered, removing from channel %s" %
                                             (subscriber["registration_id"], language))
                                subscribers.delete(subscriber)
                                self.cache.set(str('subscribers.gcm.%s' % language), subscribers)
                    if 'canonical' in response:
                        for reg_id, canonical_id in response['canonical'].items():
                            subscriber['registration_id'] = canonical_id
                    notif = {
                        "uuid": subscriber['registration_id'],
                        "type": "gcm",
                        "size": len(str(event)),
                        "time": int(time.time())
                    }
                    self.log_notification(notif)


        # Apple APNS
        subscribers = self.cache.get(str('subscribers.apns.%s' % language))
        for subscriber in subscribers:
            for event in events:
                distance = int(haversine(subscriber['coords'],
                        {'latitude': float(event['lat']), 'longitude': float(event['lng'])}))
                if distance < 10:
                    event['distance'] = distance

                    message = Message([subscriber['device_token']], alert=event['location'], badge=5)
                    res = self.apns.send(message)

                    # Check failures. Check codes in APNs reference docs.
                    for token, reason in res.failed.items():
                        code, errmsg = reason
                        self.logger.error("Device failed: {0}, reason: {1}".format(token, errmsg))
                        subscribers.remove(subscriber)
                        self.cache.set(str('subscribers.apns.%s' % language), subscribers)

                    # Check failures not related to devices.
                    for code, errmsg in res.errors:
                        self.logger.error(errmsg)

                    # Check if there are tokens that can be retried
                    if res.needs_retry():
                        retry_message = res.retry()

                    self.logger.info("Sending update to apple subscriber %s" % subscriber['device_token'])
                    notif = {
                        "uuid": subscriber['device_token'],
                        "type": "apns",
                        "size": len(str(message)),
                        "time": int(time.time())
                    }
                    self.log_notification(notif)

        callback(True)

    @tornado.gen.engine
    def feedback(self):
        """

        """
        for token, when in self.apns.feedback():
            self.logger.info("Device token %s unavailable since %s" % (token, str(when)))
            for language in ['fr', 'nl', 'de', 'en']:
                subscribers = self.cache.get(str('subscribers.apns.%s' % language))
                for subscriber in subscribers:
                    if subscriber['device_token'] == token:
                        subscribers.remove(subscriber)
                        self.cache.set(str('subscribers.apns.%s' % language), subscribers)

    @tornado.gen.engine
    def load_traffic(self):
        """

        """
        try:
            languages = ['nl', 'fr', 'de', 'en']
            for language in languages:
                self.logger.info("Fetching %s traffic ..." % language)
                new_events = yield tornado.gen.Task(self.traffic_differ, language)
                self.logger.info("Got %d new events" % len(new_events))
                if new_events is not None:
                    published = yield tornado.gen.Task(self.notify_subscribers, language, new_events)
            self.last_insert_time = int(time.time())
        except Exception as e:
            self.logger.exception(e)


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
            #SUBSCRIBE OR UPDATE
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


class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        """

        """
        return self.application.db

    @property
    def logger(self):
        """
        """
        return self.application.logger
    @property
    def gcm(self):
        """

        """
        return self.application.gcm

    @property
    def apns(self):
        """

        """
        return self.application.apns

    @property
    def cache(self):
        """

        """
        return self.application.cache

    def auth(self, username, password):
        """

        """
        authenticated = self.db.query("SELECT * FROM user WHERE username=%s AND password = UNHEX(%s)",
            username,
            hashlib.sha1(password).hexdigest())
        return authenticated


class GoogleCloudMessagingHandler(BaseHandler):

    def post(self, *args, **kwargs):
        """

        """
        try:
            self.logger.info("Request received from android device : " + self.request.body)
            data = tornado.escape.json_decode(str(self.request.body))
            if(data['registration_id'] is None or not len(data['registration_id'])):
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


class AppleSendNotificationHandler(BaseHandler):
    def get(self, *args, **kwargs):
        """

        """
        if self.get_argument("device_token") is not None and self.get_argument("message") is not None:
            message = str(self.get_argument("message"))
            device_token = self.get_argument("device_token")
            payload = None
            try:
                payload = Payload(alert=message, sound="default", badge=5)
            except PayloadTooLargeError as e:
                #if the payload is too large, we chomp the alert content
                logging.exception(e)
                json_overhead_bytes = len(payload.json()) - 1
                payload = Payload(alert=message[:(apns.MAX_PAYLOAD_LENGTH - json_overhead_bytes)],
                    sound="default", badge=5)

            self.apns.gateway_server.send_notification(device_token, payload)

        else:
            self.send_error(404)


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


class ApplePushNotificationServerHandler(BaseHandler):
    SUPPORTED_METHODS = ("POST")

    @classmethod
    def feedback(cls):
        """
            Requests APNS feedback server to remove disconnected device from list.
        """
        con = Session.new_connection("feedback_production", cert_string=db_certificate)
        service = APNs(con, tail_timeout=10)
        for token, when in service.feedback():
            cls.logger.info("Removing token %s" % token)
            for language in ['fr', 'nl', 'de', 'en']:
                subscribers = cls.cache.get(str('subscribers.apns.%s' % language))
                for subscriber in subscribers:
                    if subscriber['device_token'] == token:
                        subscribers.remove(subscriber)
                cls.cache.set('subscribers.apns.%s' % language, subscribers)

    def post(self, *args, **kwargs):
        """
            Blah blah blah
        """
        try:
            self.logger.info("Request received from iDevice : " + self.request.body)
            data = tornado.escape.json_decode(str(self.request.body))
            if data['device_token'] is None or not len(data['device_token']):
                raise AttributeError("device_token is not set")

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

            if data["coords"]["latitude"] is None or data["coords"]["longitude"] is None:
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
            subscribers = self.cache.get(str('subscribers.apns.%s' % data['language']))
            for subscriber in subscribers:
                if subscriber['device_token'] == data['device_token']:
                    subscriber = data
                    present = True

            if not present:
                data['timestamp'] = time.time()
                subscribers.append(data)

            self.cache.set(str('subscribers.apns.%s' % data['language']), subscribers)
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
    #for monitoring purpose
    def head(self, basicauth_user, basicauth_pass):
        if self.auth(basicauth_user, basicauth_pass):
            return
        else:
            self.send_error(403)


    def get(self, basicauth_user, basicauth_pass):
        """

        """
        if self.auth(basicauth_user, basicauth_pass):
            self.set_header("Content-Type", "text/html; charset=UTF-8")

            sources = [
                    {
                    'name': 'Centre Perex',
                    'url': 'http://trafiroutes.wallonie.be/trafiroutes/maptempsreel/',
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

            events_count = []
            for language in ['fr', 'nl', 'de', 'en']:
                events_count.append(len(self.db.query(
                    "SELECT * FROM trafic WHERE language = \"%s\" AND time >= CURRENT_DATE" % (language))))

            google_subscribers = dict(
                fr=self.cache.get('subscribers.gcm.fr'),
                nl=self.cache.get('subscribers.gcm.nl'),
                de=self.cache.get('subscribers.gcm.de'),
                en=self.cache.get('subscribers.gcm.en')
            )
            apple_subscribers = dict(
                fr=self.cache.get('subscribers.apns.fr'),
                nl=self.cache.get('subscribers.apns.nl'),
                de=self.cache.get('subscribers.apns.de'),
                en=self.cache.get('subscribers.apns.en')
            )
            web_subscribers = dict(
                fr=self.cache.get('subscribers.web.fr'),
                nl=self.cache.get('subscribers.web.nl'),
                de=self.cache.get('subscribers.web.de'),
                en=self.cache.get('subscribers.web.en')
            )

            apple_total = sum(len(v) for v in apple_subscribers.itervalues())
            self.render("templates/index.html", username=basicauth_user, sources=sources,
                traffic_feed_channels=['fr', 'nl', 'de', 'en'], google_subscribers=google_subscribers,
                events_count=events_count, apple_subscribers=apple_subscribers, apple_total=apple_total,
                web_subscribers=web_subscribers,
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

        data = {}
        if self.auth(basicauth_user, basicauth_pass):
            if subscriber_type in self.subscribers_types:
                if subscriber_type == "web":
                    data = dict(
                        fr=self.cache.get('subscribers.web.fr'),
                        nl=self.cache.get('subscribers.web.nl'),
                        de=self.cache.get('subscribers.web.de'),
                        en=self.cache.get('subscribers.web.en')
                    )
                elif subscriber_type == "google":
                    data = dict(
                        fr=self.cache.get('subscribers.gcm.fr'),
                        nl=self.cache.get('subscribers.gcm.nl'),
                        de=self.cache.get('subscribers.gcm.de'),
                        en=self.cache.get('subscribers.gcm.en')
                    )
                elif subscriber_type == "apple":
                    data = dict(
                        fr=self.cache.get('subscribers.apns.fr'),
                        nl=self.cache.get('subscribers.apns.nl'),
                        de=self.cache.get('subscribers.apns.de'),
                        en=self.cache.get('subscribers.apns.en')
                    )

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
                os
              FROM requests
              WHERE LOWER(`user_agent`) NOT LIKE "%%curl%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%python%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%wget%%" AND time >= %s AND
              time <= %s AND package LIKE %s AND resource LIKE %s GROUP BY os ORDER BY time DESC""",
            int(start_date), int(end_date), str(package), str(resource))
        data = []
        try:
            for row in rows:
                data.append({
                    'name': row['os'] if row['os'] is not None else "other",
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
                SELECT COUNT(*) as total, browser
                  FROM requests
                  WHERE LOWER(`user_agent`) NOT LIKE "%%curl%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%python%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
                   AND time >= %s AND time <= %s AND package LIKE %s AND resource LIKE %s
                  GROUP BY browser
                  ORDER BY time DESC""",
            int(start_date), int(end_date), package, resource)

        data = []
        try:
            for row in rows:
                data.append({
                    'name': row['browser'] if row['browser'] is not None else "other",
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
        d = {'hourly': 'hour', 'daily': 'day', 'weekly': 'week', 'monthly': 'month', 'yearly': 'year'}

        rows = self.db.query("""
                        SELECT
                            COUNT(*) as hits,
                            FROM_UNIXTIME(time, \"%%h:%%m %%d-%%m-%%Y\") as name,
                            FROM_UNIXTIME(time, \"%%h %%d-%%m-%%Y\") as hour,
                            FROM_UNIXTIME(time, \"%%d-%%m-%%Y\") as day,
                            FROM_UNIXTIME(time, \"%%u-%%Y\") as week,
                            FROM_UNIXTIME(time, \"%%m-%%Y\") as month,
                            FROM_UNIXTIME(time, \"%%Y\") as year
                            FROM requests
                            WHERE time >= %s AND time <= %s AND package LIKE %s AND
                    resource LIKE %s
                    AND LOWER(`user_agent`) NOT LIKE "%%curl%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%python%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
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
class AnalyticsNotificationsHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, frequency, basicauth_user, basicauth_pass):
        """

        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())

            data = yield tornado.gen.Task(self.parse_notifications, start_date, end_date, frequency)
            self.set_header("Content-Type", "text/json; charset=UTF-8")
            self.write(tornado.escape.json_encode(data))
            self.finish()

        else:
            self.write_error(403)


    def parse_notifications(self, start_date, end_date, frequency, callback):
        d = {'hourly': 'hour', 'daily': 'day', 'weekly': 'week', 'monthly': 'month', 'yearly': 'year'}

        rows = self.db.query("""
                        SELECT
                            COUNT(*) as notifications,
                            type,
                            FROM_UNIXTIME(time, \"%%h:%%m %%d-%%m-%%Y\") as name,
                            FROM_UNIXTIME(time, \"%%h %%d-%%m-%%Y\") as hour,
                            FROM_UNIXTIME(time, \"%%d-%%m-%%Y\") as day,
                            FROM_UNIXTIME(time, \"%%u-%%Y\") as week,
                            FROM_UNIXTIME(time, \"%%m-%%Y\") as month,
                            FROM_UNIXTIME(time, \"%%Y\") as year
                            FROM notification_logs
                            WHERE time >= %s AND time <= %s
                    GROUP BY """ + d[frequency] + """, type ORDER BY time ASC
                    """, int(start_date), int(end_date))

        data = [{}]
        try:
            for row in rows:
                if row['type'] not in data[0]:
                    data[0][row['type']] = []
                data[0][row['type']].append({
                    'name': row['name'],
                    'total': int(row['notifications'])
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
            SELECT language,
                COUNT(id) AS hits,
                language
		FROM
                    requests
                WHERE
                    LOWER(`user_agent`) NOT LIKE "%%curl%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%python%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
                AND time >= %s AND time <= %s AND package LIKE %s AND
                    resource LIKE %s GROUP BY language ORDER BY hits DESC
                    """, int(start_date), int(end_date), package, resource)

        data = []
        try:
            for row in rows:
                data.append({
                    'name': row['language'] if row['language'] is not None else "other",
                    'total': int(row['hits'])
                })
            callback(data)
        except Exception, e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsDeviceHandler(BaseHandler):
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
            device
            FROM requests
            WHERE time >= %s AND time <= %s AND package LIKE %s
            AND resource LIKE %s
            AND LOWER(`user_agent`) NOT LIKE "%%curl%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%python%%"
                    AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
            GROUP BY device ORDER BY time DESC""", int(start_date), int(end_date), package, resource)

        data = []
        try:
            for row in rows:
                data.append({
                    'name': row['device'] if row['device'] is not None else "other",
                    'total': int(row['total'])
                })
            callback(data)
        except Exception, e:
            logging.error(e)
            callback(data)
        return


if __name__ == "__main__":

    try:
        parser = OptionParser()
        parser.add_option("-c", "--config", type="string", default="%s/config.ini"%os.path.dirname(os.path.abspath(__file__)) , help="configuration file")
        (options, args) = parser.parse_args()

        print hashlib.sha1('lioneldashboard').hexdigest()
        config = configparser.ConfigParser()
        config.read(options.config)

        app = Application(config)

        app.listen(int(config['server']['port']))
        logging.info("BeRoads webserver listening on %s" % (config['server']['port']))
        main_loop = tornado.ioloop.IOLoop.instance()

        tornado.ioloop.PeriodicCallback(
            app.load_traffic,
            int(config['server']['update_time'])*1000,
            io_loop=main_loop
        ).start()

        feedback_callback = tornado.ioloop.PeriodicCallback(
            app.feedback,
            int(config['server']['update_time'])*1000
        ).start()

        main_loop.start()
    except KeyboardInterrupt as e:
        logging.exception(e)
        sys.exit(0)
