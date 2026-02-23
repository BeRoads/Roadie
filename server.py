# -*- coding: utf-8 -*-

__author__ = 'quentinkaiser'

import configparser
import logging
import os
import sys
import time
from optparse import OptionParser

import memcache
import tornado.escape
import tornado.gen
import tornado.ioloop
import tornado.web
import tornado.websocket

from db.async_pool import AsyncPyMySQLPool
from geo_util import haversine, nearest_point_segment
from handlers.analytics import *
from handlers.apns import *
from handlers.base import *
from handlers.dashboard import *
from handlers.deployment import *
from handlers.gcm import FCMRegistrationHandler, GoogleCloudMessagingHandler
from handlers.traffic import *
from handlers.websocket import *
from push.gateway import PushGateway


class Application(tornado.web.Application):
    def __init__(self, config):
        self.config = config

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
            (r"/gcm", GoogleCloudMessagingHandler),  # legacy alias kept for compatibility
            (r"/fcm", FCMRegistrationHandler),
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
            (r"/deployment/([0-9a-zA-Z_\-]+)", DeploymentHandler),
        ]

        tornado.web.Application.__init__(self, handlers, **settings)

        self.last_insert_time = int(time.time())

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

        self.push_gateway = PushGateway(
            config=self.config,
            logger=self.logger,
            base_dir=os.path.dirname(os.path.abspath(__file__)),
        )
        # Compatibility attributes used by old handlers/base properties.
        self.gcm = self.push_gateway
        self.apns = self.push_gateway

        # Keep the old execute() contract but use a Python 3 compatible DB adapter.
        self.db = AsyncPyMySQLPool(
            host=self.config['mysql']['host'],
            port=self.config['mysql'].get('port', 3306),
            database=self.config['mysql']['database'],
            user=self.config['mysql']['username'],
            password=self.config['mysql']['password'],
            max_workers=int(self.config['mysql'].get('pool_workers', 4)),
        )

        self.cache = memcache.Client(
            ['%s:%d' % (self.config['memcached']['ip'], int(self.config['memcached']['port']))],
            debug=True,
        )

        self._bootstrap_cache()

    def _bootstrap_cache(self):
        for contype in ['gcm', 'fcm', 'web']:
            for language in ['fr', 'nl', 'de', 'en']:
                key = str('subscribers.%s.%s' % (contype, language))
                if self.cache.get(key) is None:
                    self.cache.set(key, [])

        for language in ['fr', 'nl', 'de', 'en']:
            legacy_key = str('subscribers.apns.%s' % language)
            if self.cache.get(legacy_key) is None:
                self.cache.set(legacy_key, [])
            for mode in ['production', 'sandbox']:
                key = str('subscribers.apns.%s.%s' % (mode, language))
                if self.cache.get(key) is None:
                    self.cache.set(key, [])

    @staticmethod
    def _normalize_geo_point(coords):
        latitude = coords.get('latitude', coords.get('lat'))
        longitude = coords.get('longitude', coords.get('lng'))
        if latitude is None or longitude is None:
            return None
        return {'latitude': float(latitude), 'longitude': float(longitude)}

    def _distance_for_subscriber(self, subscriber, event):
        event_coords = {'latitude': float(event['lat']), 'longitude': float(event['lng'])}
        subscriber_coords = self._normalize_geo_point(subscriber.get('coords', {}))
        if subscriber_coords is None:
            return sys.maxsize

        points = subscriber.get('points')
        if points and len(points) > 1:
            nearest_distance = sys.maxsize
            for i in range(1, len(points)):
                current_point = self._normalize_geo_point(points[i - 1])
                next_point = self._normalize_geo_point(points[i])
                if current_point is None or next_point is None:
                    continue
                projection_input = {
                    'coords': subscriber_coords,
                    'latitude': subscriber_coords['latitude'],
                    'longitude': subscriber_coords['longitude'],
                }
                projected = nearest_point_segment(current_point, next_point, projection_input)
                nearest_distance = min(
                    nearest_distance,
                    int(haversine(projected, subscriber_coords)),
                )
            if nearest_distance != sys.maxsize:
                return nearest_distance

        return int(haversine(subscriber_coords, event_coords))

    @tornado.gen.coroutine
    def log_notification(self, notif):
        """
            Logs a notification into our mysql database
        """
        self.logger.info("Insert log notification : %s", notif)
        yield self.db.execute(
            "INSERT INTO notification_logs (uuid, type, size, time, language, sandbox) VALUES (%s, %s, %s, %s, %s, %s)",
            notif['uuid'],
            notif['type'],
            notif['size'],
            notif['time'],
            notif['language'],
            notif['sandbox'],
        )

    @tornado.gen.coroutine
    def traffic_differ(self, language):
        # traffic differ with mysql stored events (md5 hash)
        try:
            sandbox_mode = int(bool(self.config['push'].getboolean('apns_sandbox_mode')))
            last_notification_cursor = yield self.db.execute(
                "SELECT * FROM `notification_logs` WHERE type = %s AND language = %s AND sandbox = %s ORDER BY id DESC LIMIT 1",
                "apns",
                language,
                sandbox_mode,
            )
            last_notification = last_notification_cursor.fetchone()
            self.logger.info("Last_notication %s", last_notification)
            if last_notification is None:
                new_events_cursor = yield self.db.execute(
                    "SELECT * FROM `trafic` WHERE `language` = %s AND `insert_time` > UNIX_TIMESTAMP(CURDATE())",
                    language,
                )
                new_events = new_events_cursor.fetchall()
            else:
                new_events_cursor = yield self.db.execute(
                    "SELECT * FROM `trafic` WHERE `language` = %s AND `insert_time` > %s",
                    language,
                    int(last_notification['time']),
                )
                new_events = new_events_cursor.fetchall()
            return new_events
        except Exception as e:
            logging.error(e)
            return None

    @tornado.gen.coroutine
    def notify_subscribers(self, language, events):
        sandbox_mode = self.push_gateway.apns_environment
        sandbox_flag = int(bool(self.config['push'].getboolean('apns_sandbox_mode')))

        self.logger.info("Notifying subscribers from channel %s", language)

        # Websocket subscribers
        web_subscribers = self.cache.get(str('subscribers.web.%s' % language))
        if not web_subscribers:
            web_subscribers = []

        for subscriber in web_subscribers:
            for event in events:
                distance = int(haversine(subscriber.coords, {'latitude': float(event['lat']), 'longitude': float(event['lng'])}))
                if distance < int(subscriber.area):
                    event_payload = dict(event)
                    event_payload['distance'] = distance
                    message = {
                        "uuid": subscriber.uuid,
                        "code": 3,
                        "data": event_payload,
                    }
                    try:
                        subscriber.write_message(tornado.escape.json_encode(message))
                    except Exception as exc:
                        self.logger.error("Websocket push failed for %s: %s", subscriber.uuid, exc)
                        continue

                    yield self.log_notification(
                        {
                            "uuid": subscriber.uuid,
                            "type": "web",
                            "size": len(str(event_payload)),
                            "time": int(time.time()),
                            "sandbox": sandbox_flag,
                            "language": language,
                        }
                    )

        # Android subscribers (FCM, keep GCM key as alias)
        fcm_key = str('subscribers.fcm.%s' % language)
        gcm_legacy_key = str('subscribers.gcm.%s' % language)
        fcm_subscribers = self.cache.get(fcm_key)
        if fcm_subscribers is None:
            fcm_subscribers = self.cache.get(gcm_legacy_key)
        if not fcm_subscribers:
            fcm_subscribers = []

        surviving_fcm_subscribers = []
        for subscriber in fcm_subscribers:
            token = subscriber.get('fcm_token') or subscriber.get('registration_id')
            keep_subscriber = True
            if not token:
                continue

            for event in events:
                distance = self._distance_for_subscriber(subscriber, event)
                if distance >= int(subscriber.get('area', 0)):
                    continue

                event_payload = dict(event)
                event_payload['distance'] = distance
                sent, details, should_drop = self.push_gateway.send_fcm_notification(
                    registration_token=token, data=event_payload
                )
                if sent:
                    yield self.log_notification(
                        {
                            "uuid": token,
                            "type": "fcm",
                            "size": len(str(event_payload)),
                            "time": int(time.time()),
                            "sandbox": sandbox_flag,
                            "language": language,
                        }
                    )
                else:
                    self.logger.error("FCM send failed for %s: %s", token, details)
                    if should_drop:
                        keep_subscriber = False
                        break

            if keep_subscriber:
                surviving_fcm_subscribers.append(subscriber)

        self.cache.set(fcm_key, surviving_fcm_subscribers)
        self.cache.set(gcm_legacy_key, surviving_fcm_subscribers)

        # Apple subscribers
        apns_key = str('subscribers.apns.%s.%s' % (sandbox_mode, language))
        apns_legacy_key = str('subscribers.apns.%s' % language)
        apns_subscribers = self.cache.get(apns_key)
        if not apns_subscribers:
            apns_subscribers = []

        surviving_apns_subscribers = []
        for subscriber in apns_subscribers:
            keep_subscriber = True
            token = subscriber.get('device_token')
            if not token:
                continue

            for event in events:
                distance = self._distance_for_subscriber(subscriber, event)
                target_area = int(subscriber.get('area', 10))
                if distance >= target_area:
                    continue

                event_payload = dict(event)
                event_payload['distance'] = distance
                sent, details, should_drop = self.push_gateway.send_apns_notification(
                    device_token=token,
                    alert=str(event.get('location', 'Traffic update')),
                    custom={'id': str(event.get('id', ''))},
                )
                if sent:
                    yield self.log_notification(
                        {
                            "uuid": token,
                            "type": "apns",
                            "size": len(str(event_payload)),
                            "time": int(time.time()),
                            "sandbox": sandbox_flag,
                            "language": language,
                        }
                    )
                else:
                    self.logger.error("APNS send failed for %s: %s", token, details)
                    if should_drop:
                        keep_subscriber = False
                        break

            if keep_subscriber:
                surviving_apns_subscribers.append(subscriber)

        self.cache.set(apns_key, surviving_apns_subscribers)
        self.cache.set(apns_legacy_key, surviving_apns_subscribers)
        return True

    @tornado.gen.coroutine
    def feedback(self):
        # APNS feedback service was deprecated by Apple; token invalidation is handled by send responses.
        return

    @tornado.gen.coroutine
    def load_traffic(self):
        try:
            for language in ['nl', 'fr', 'de', 'en']:
                self.logger.info("Fetching %s traffic ...", language)
                new_events = yield self.traffic_differ(language)
                if not new_events:
                    self.logger.info("Got 0 event")
                else:
                    self.logger.info("Got %d new events", len(new_events))
                    yield self.notify_subscribers(language, new_events)
                    self.last_insert_time = int(time.time())
        except Exception as e:
            self.logger.exception(e)


if __name__ == "__main__":
    try:
        parser = OptionParser()
        parser.add_option(
            "-c",
            "--config",
            type="string",
            default="%s/config.ini" % os.path.dirname(os.path.abspath(__file__)),
            help="configuration file",
        )
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
            io_loop=main_loop,
        ).start()

        tornado.ioloop.PeriodicCallback(
            app.feedback,
            int(config['server']['update_time']) * 1000,
        ).start()

        main_loop.start()
    except KeyboardInterrupt as e:
        logging.exception(e)
        sys.exit(0)
