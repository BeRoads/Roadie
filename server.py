# -*- coding: utf-8 -*-
__author__ = 'quentinkaiser'
import os
import sys
import configparser
from optparse import OptionParser

import tornado.escape
import tornado.ioloop
from tornado.options import options
import tornado.web
import tornado.websocket
import tornado.gen
from tornado_mysql import pools
import memcache
from gcm import *
from apns_clerk import *
from apns_clerk.backends.stdio import Certificate
from handlers.analytics import *
from handlers.apns import *
from handlers.base import *
from handlers.dashboard import *
from handlers.deployment import *
from handlers.gcm import *
from handlers.traffic import *
from handlers.websocket import *
from geo_util import *

class Application(tornado.web.Application):
    def __init__(self, config):


        settings = dict(
            cookie_secret="5725af95ef74805b753cd3689bb3393681e02ce6",
            static_path=os.path.join(os.path.dirname(__file__), "static"),
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
        if not self.config['push']['apns_sandbox_mode']:
            print("Use APNS Production")
            con = session.get_connection("push_production", cert_file='%s/%s' % (os.path.dirname(os.path.abspath(__file__)), self.config['push']['apns_certificate']),
                                     key_file='%s/%s' % (os.path.dirname(os.path.abspath(__file__)), self.config['push']['apns_key']),
                                     passphrase=str(self.config['push']['apns_passphrase']))
            self.apns = APNs(con)
        else:
            print("Use APNS Sandbox")
            con = session.get_connection("push_sandbox", cert_file='%s/%s' % (os.path.dirname(os.path.abspath(__file__)), self.config['push']['apns_certificate']),
                                     key_file='%s/%s' % (os.path.dirname(os.path.abspath(__file__)), self.config['push']['apns_key']),
                                     passphrase=str(self.config['push']['apns_passphrase']))
            self.apns = APNs(con)

        # Have one global connection to the TDT DB across all handlers
        pools.DEBUG = True
        self.db = pools.Pool(
            dict(
                host=self.config['mysql']['host'],
                port=3306,
                database=self.config['mysql']['database'],
                user=self.config['mysql']['username'],
                password=self.config['mysql']['password']
            ),
            max_idle_connections=1,
            max_recycle_sec=3)

        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("server")
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


    @tornado.gen.coroutine
    def log_notification(self, notif):
        """
            Logs a notification into our mysql database
        """
        self.db.execute("INSERT INTO notification_logs (uuid, type, size, time) VALUES "
                        "(\"%s\", \"%s\", %d, %d)" %
                        (notif['uuid'], notif['type'], notif['size'], notif['time']))
        return

    @tornado.gen.coroutine
    def traffic_differ(self, language):
        # traffic differ with mysql stored events (md5 hash)
        try:
            rows = yield self.db.execute("SELECT * FROM trafic WHERE language = '%s' AND insert_time > %d" % (language, self.last_insert_time))
            return rows.fetchall()
        except Exception as e:
            logging.error(e)
            return None


    @tornado.gen.coroutine
    def notify_subscribers(self, language, events):
        """
        """
        self.logger.info("Notifying subscribers from channel %s" % language)

        for subscriber in self.cache.get(str('subscribers.web.%s' % language)) or []:
            for event in events:
                distance = int(haversine(subscriber.coords,
                                         {'latitude': float(event['lat']), 'longitude': float(event['lng'])}))
                if distance < int(subscriber.area):
                    event['distance'] = distance
                    # PUBLISH
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
                        # compute distance between a point (the event coordinates) and
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
                    self.logger.info(
                        "Sending update %s to google subscriber %s" % (event, subscriber['registration_id']))
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
        if not self.config['push']['apns_sandbox_mode']:
            sandbox_mode = "production"
        else:
            sandbox_mode = "sandbox"
        subscribers = self.cache.get(str('subscribers.apns.%s.%s' % (sandbox_mode, language)))
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
                        self.cache.set(str('subscribers.apns.%s.%s' % (sandbox_mode, language)), subscribers)

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

        return True

    @tornado.gen.coroutine
    def feedback(self):
        """

        """
        session = Session()
        certificate = Certificate(cert_file='%s/%s' % (os.path.dirname(os.path.abspath(__file__)), self.config['push']['apns_certificate']),
                                      key_file='%s/%s' % (os.path.dirname(os.path.abspath(__file__)), self.config['push']['apns_key']),
                                      passphrase=str(self.config['push']['apns_passphrase']))
        if not self.config['push']['apns_sandbox_mode']:
            sandbox_mode = "production"
            self.logger.info("Use APNS Feedback Production")
            con = session.new_connection("feedback_production", certificate)
        else:
            sandbox_mode = "sandbox"
            self.logger.info("Use APNS Feedback Sandbox")
            con = session.new_connection("feedback_sandbox", certificate)

        apns_feedback = APNs(con)

        for token, when in apns_feedback.feedback():
            self.logger.info("Device token %s unavailable since %s" % (token, str(when)))
            for language in ['fr', 'nl', 'de', 'en']:
                subscribers = self.cache.get(str('subscribers.apns.%s.%s' % (sandbox_mode, language)))
                for subscriber in subscribers:
                    if subscriber['device_token'] == token:
                        subscribers.remove(subscriber)
                        self.cache.set(str('subscribers.apns.%s.%s' % (sandbox_mode, language)), subscribers)

    @tornado.gen.coroutine
    def load_traffic(self):
        """

        """
        try:
            languages = ['nl', 'fr', 'de', 'en']
            for language in languages:
                self.logger.info("Fetching %s traffic ..." % language)
                new_events = yield tornado.gen.Task(self.traffic_differ, language)
                if not new_events:
                    self.logger.info("Got 0 event")
                else:
                    self.logger.info("Got %d new events" % len(new_events))
                    published = yield tornado.gen.Task(self.notify_subscribers, language, new_events)
                    self.last_insert_time = int(time.time())
        except Exception as e:
            self.logger.exception(e)


if __name__ == "__main__":

    try:
        parser = OptionParser()
        parser.add_option("-c", "--config", type="string",
                          default="%s/config.ini" % os.path.dirname(os.path.abspath(__file__)),
                          help="configuration file")
        (options, args) = parser.parse_args()

        config = configparser.ConfigParser()
        config.read(options.config)

        app = Application(config)

        app.listen(int(config['server']['port']))
        print("BeRoads webserver listening on %s" % (config['server']['port']))
        main_loop = tornado.ioloop.IOLoop.instance()

        tornado.ioloop.PeriodicCallback(
            app.load_traffic,
            int(config['server']['update_time']) * 1000,
            io_loop=main_loop
        ).start()

        feedback_callback = tornado.ioloop.PeriodicCallback(
            app.feedback,
            int(config['server']['update_time']) * 1000
        ).start()

        main_loop.start()
    except KeyboardInterrupt as e:
        logging.exception(e)
        sys.exit(0)
