import logging
import time

import tornado.escape
import tornado.gen

from handlers.base import BaseHandler
from handlers.require_basic_auth import require_basic_auth

__author__ = 'lionelschinckus'


class AnalyticsMixin(object):
    @tornado.gen.coroutine
    def _is_authorized(self, basicauth_user, basicauth_pass):
        authenticated = yield self.auth(basicauth_user, basicauth_pass)
        if not authenticated:
            self.write_error(403)
            return False
        return True

    @tornado.gen.coroutine
    def _normalize_scope(self, package, resource):
        package_present = yield self.db.execute(
            "SELECT * FROM package WHERE package_name = %s", str(package)
        )
        resource_present = yield self.db.execute(
            "SELECT * FROM resource WHERE resource_name = %s", str(resource)
        )

        if (package != 'all' and not package_present) or (resource != 'all' and not resource_present):
            self.write_error(404)
            return None, None

        if package == "all":
            package = "%"
        if resource == "all":
            resource = "%"
        return package, resource

    def _json(self, data):
        self.set_header("Content-Type", "text/json; charset=UTF-8")
        self.write(tornado.escape.json_encode(data))


@require_basic_auth
class AnalyticsSubscribersHandler(AnalyticsMixin, BaseHandler):
    subscribers_types = ['web', 'apple', 'google']

    @tornado.gen.coroutine
    def get(self, subscriber_type, basicauth_user, basicauth_pass):
        if not (yield self._is_authorized(basicauth_user, basicauth_pass)):
            return

        if subscriber_type not in self.subscribers_types:
            self.write_error(404)
            return

        sandbox_mode = "sandbox" if self.config['push'].getboolean('apns_sandbox_mode') else "production"
        if subscriber_type == "web":
            data = dict(
                fr=self.cache.get('subscribers.web.fr') or [],
                nl=self.cache.get('subscribers.web.nl') or [],
                de=self.cache.get('subscribers.web.de') or [],
                en=self.cache.get('subscribers.web.en') or [],
            )
        elif subscriber_type == "google":
            data = dict(
                fr=self.cache.get('subscribers.fcm.fr') or self.cache.get('subscribers.gcm.fr') or [],
                nl=self.cache.get('subscribers.fcm.nl') or self.cache.get('subscribers.gcm.nl') or [],
                de=self.cache.get('subscribers.fcm.de') or self.cache.get('subscribers.gcm.de') or [],
                en=self.cache.get('subscribers.fcm.en') or self.cache.get('subscribers.gcm.en') or [],
            )
        else:  # apple
            data = dict(
                fr=self.cache.get('subscribers.apns.%s.fr' % sandbox_mode) or self.cache.get('subscribers.apns.fr') or [],
                nl=self.cache.get('subscribers.apns.%s.nl' % sandbox_mode) or self.cache.get('subscribers.apns.nl') or [],
                de=self.cache.get('subscribers.apns.%s.de' % sandbox_mode) or self.cache.get('subscribers.apns.de') or [],
                en=self.cache.get('subscribers.apns.%s.en' % sandbox_mode) or self.cache.get('subscribers.apns.en') or [],
            )

        self._json(data)


@require_basic_auth
class AnalyticsOSHandler(AnalyticsMixin, BaseHandler):
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        if not (yield self._is_authorized(basicauth_user, basicauth_pass)):
            return

        package, resource = yield self._normalize_scope(package, resource)
        if package is None:
            return

        start_date = int(self.get_argument('start_date', 0))
        end_date = int(self.get_argument('end_date', time.time()))
        data = yield self.parse_user_agents(package, resource, start_date, end_date)
        self._json(data)

    @tornado.gen.coroutine
    def parse_user_agents(self, package, resource, start_date, end_date):
        rows = yield self.db.execute(
            """
            SELECT COUNT(*) as total, os
            FROM requests
            WHERE LOWER(`user_agent`) NOT LIKE "%%curl%%"
              AND LOWER(`user_agent`) NOT LIKE "%%python%%"
              AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
              AND time >= %s
              AND time <= %s
              AND package LIKE %s
              AND resource LIKE %s
            GROUP BY os
            ORDER BY time DESC
            """,
            start_date,
            end_date,
            str(package),
            str(resource),
        )
        data = []
        for row in rows:
            data.append({'name': row['os'] if row['os'] is not None else "other", 'total': int(row['total'])})
        return data


@require_basic_auth
class AnalyticsBrowserHandler(AnalyticsMixin, BaseHandler):
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        if not (yield self._is_authorized(basicauth_user, basicauth_pass)):
            return

        package, resource = yield self._normalize_scope(package, resource)
        if package is None:
            return

        start_date = int(self.get_argument('start_date', 0))
        end_date = int(self.get_argument('end_date', time.time()))
        data = yield self.parse_user_agents(package, resource, start_date, end_date)
        self._json(data)

    @tornado.gen.coroutine
    def parse_user_agents(self, package, resource, start_date, end_date):
        rows = yield self.db.execute(
            """
            SELECT COUNT(*) as total, browser
            FROM requests
            WHERE LOWER(`user_agent`) NOT LIKE "%%curl%%"
              AND LOWER(`user_agent`) NOT LIKE "%%python%%"
              AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
              AND time >= %s
              AND time <= %s
              AND package LIKE %s
              AND resource LIKE %s
            GROUP BY browser
            ORDER BY time DESC
            """,
            start_date,
            end_date,
            package,
            resource,
        )
        data = []
        for row in rows:
            data.append({'name': row['browser'] if row['browser'] is not None else "other", 'total': int(row['total'])})
        return data


@require_basic_auth
class AnalyticsCoordinateHandler(AnalyticsMixin, BaseHandler):
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        if not (yield self._is_authorized(basicauth_user, basicauth_pass)):
            return

        package, resource = yield self._normalize_scope(package, resource)
        if package is None:
            return

        start_date = int(self.get_argument('start_date', 0))
        end_date = int(self.get_argument('end_date', time.time()))
        data = yield self.parse_coordinates(package, resource, start_date, end_date)
        self._json(data)

    @tornado.gen.coroutine
    def parse_coordinates(self, package, resource, start_date, end_date):
        rows = yield self.db.execute(
            """
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
                    ), '&', 1
                ) AS url
            FROM requests
            WHERE `url_request` LIKE "%%from=%%&area=%%"
              AND time >= %s
              AND time <= %s
              AND package LIKE %s
              AND resource LIKE %s
            ORDER BY time DESC
            """,
            start_date,
            end_date,
            package,
            resource,
        )

        data = []
        for row in rows:
            try:
                coords = row['url'].split(',')
                data.append({'lat': float(coords[0]), 'lng': float(coords[1]), 'count': 1})
            except Exception:
                continue
        return data


@require_basic_auth
class AnalyticsHitHandler(AnalyticsMixin, BaseHandler):
    @tornado.gen.coroutine
    def get(self, package, resource, frequency, basicauth_user, basicauth_pass):
        if not (yield self._is_authorized(basicauth_user, basicauth_pass)):
            return

        package, resource = yield self._normalize_scope(package, resource)
        if package is None:
            return

        start_date = int(self.get_argument('start_date', 0))
        end_date = int(self.get_argument('end_date', time.time()))
        data = yield self.parse_hits(package, resource, start_date, end_date, frequency)
        self._json(data)

    @tornado.gen.coroutine
    def parse_hits(self, package, resource, start_date, end_date, frequency):
        d = {'hourly': 'hour', 'daily': 'day', 'weekly': 'week', 'monthly': 'month', 'yearly': 'year'}
        group_by = d.get(frequency, 'day')

        rows = yield self.db.execute(
            """
            SELECT
                COUNT(*) as hits,
                FROM_UNIXTIME(time, "%%h:%%m %%d-%%m-%%Y") as name,
                FROM_UNIXTIME(time, "%%h %%d-%%m-%%Y") as hour,
                FROM_UNIXTIME(time, "%%d-%%m-%%Y") as day,
                FROM_UNIXTIME(time, "%%u-%%Y") as week,
                FROM_UNIXTIME(time, "%%m-%%Y") as month,
                FROM_UNIXTIME(time, "%%Y") as year
            FROM requests
            WHERE time >= %s
              AND time <= %s
              AND package LIKE %s
              AND resource LIKE %s
              AND LOWER(`user_agent`) NOT LIKE "%%curl%%"
              AND LOWER(`user_agent`) NOT LIKE "%%python%%"
              AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
            GROUP BY """
            + group_by
            + """
            ORDER BY time ASC
            """,
            start_date,
            end_date,
            str(package),
            str(resource),
        )

        data = []
        for row in rows:
            data.append({'name': row['name'], 'total': int(row['hits'])})
        return data


@require_basic_auth
class AnalyticsNotificationsHandler(AnalyticsMixin, BaseHandler):
    @tornado.gen.coroutine
    def get(self, frequency, basicauth_user, basicauth_pass):
        if not (yield self._is_authorized(basicauth_user, basicauth_pass)):
            return

        start_date = int(self.get_argument('start_date', 0))
        end_date = int(self.get_argument('end_date', time.time()))
        data = yield self.parse_notifications(start_date, end_date, frequency)
        self._json(data)

    @tornado.gen.coroutine
    def parse_notifications(self, start_date, end_date, frequency):
        d = {'hourly': 'hour', 'daily': 'day', 'weekly': 'week', 'monthly': 'month', 'yearly': 'year'}
        group_by = d.get(frequency, 'day')

        rows = yield self.db.execute(
            """
            SELECT
                COUNT(*) as notifications,
                type,
                FROM_UNIXTIME(time, "%%h:%%m %%d-%%m-%%Y") as name,
                FROM_UNIXTIME(time, "%%h %%d-%%m-%%Y") as hour,
                FROM_UNIXTIME(time, "%%d-%%m-%%Y") as day,
                FROM_UNIXTIME(time, "%%u-%%Y") as week,
                FROM_UNIXTIME(time, "%%m-%%Y") as month,
                FROM_UNIXTIME(time, "%%Y") as year
            FROM notification_logs
            WHERE time >= %s
              AND time <= %s
            GROUP BY """
            + group_by
            + """, type
            ORDER BY time ASC
            """,
            start_date,
            end_date,
        )

        data = [{}]
        for row in rows:
            if row['type'] not in data[0]:
                data[0][row['type']] = []
            data[0][row['type']].append({'name': row['name'], 'total': int(row['notifications'])})
        return data


@require_basic_auth
class AnalyticsLanguageHandler(AnalyticsMixin, BaseHandler):
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        if not (yield self._is_authorized(basicauth_user, basicauth_pass)):
            return

        package, resource = yield self._normalize_scope(package, resource)
        if package is None:
            return

        start_date = int(self.get_argument('start_date', 0))
        end_date = int(self.get_argument('end_date', time.time()))
        data = yield self.parse_languages(package, resource, start_date, end_date)
        self._json(data)

    @tornado.gen.coroutine
    def parse_languages(self, package, resource, start_date, end_date):
        rows = yield self.db.execute(
            """
            SELECT language, COUNT(id) AS hits, language
            FROM requests
            WHERE LOWER(`user_agent`) NOT LIKE "%%curl%%"
              AND LOWER(`user_agent`) NOT LIKE "%%python%%"
              AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
              AND time >= %s
              AND time <= %s
              AND package LIKE %s
              AND resource LIKE %s
            GROUP BY language
            ORDER BY hits DESC
            """,
            start_date,
            end_date,
            package,
            resource,
        )

        data = []
        for row in rows:
            data.append({'name': row['language'] if row['language'] is not None else "other", 'total': int(row['hits'])})
        return data


@require_basic_auth
class AnalyticsDeviceHandler(AnalyticsMixin, BaseHandler):
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        if not (yield self._is_authorized(basicauth_user, basicauth_pass)):
            return

        package, resource = yield self._normalize_scope(package, resource)
        if package is None:
            return

        start_date = int(self.get_argument('start_date', 0))
        end_date = int(self.get_argument('end_date', time.time()))
        data = yield self.parse_user_agents(package, resource, start_date, end_date)
        self._json(data)

    @tornado.gen.coroutine
    def parse_user_agents(self, package, resource, start_date, end_date):
        rows = yield self.db.execute(
            """
            SELECT COUNT(*) as total, device
            FROM requests
            WHERE time >= %s
              AND time <= %s
              AND package LIKE %s
              AND resource LIKE %s
              AND LOWER(`user_agent`) NOT LIKE "%%curl%%"
              AND LOWER(`user_agent`) NOT LIKE "%%python%%"
              AND LOWER(`user_agent`) NOT LIKE "%%wget%%"
            GROUP BY device
            ORDER BY time DESC
            """,
            start_date,
            end_date,
            package,
            resource,
        )

        data = []
        for row in rows:
            data.append({'name': row['device'] if row['device'] is not None else "other", 'total': int(row['total'])})
        return data

