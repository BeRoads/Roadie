import logging
import time
from handlers.base import BaseHandler
from handlers.require_basic_auth import require_basic_auth
import tornado.escape
import tornado.gen
import tornado.web

__author__ = 'lionelschinckus'


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
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        """
            Request all user agents for specific TDT package and resource between start_date and end_date if provided.
            Compute per OS requests percentage and send them back.
        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())

            package_present = yield self.db.execute("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = yield self.db.execute("SELECT * FROM resource WHERE resource_name = %s", str(resource))

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

    @tornado.gen.coroutine
    def parse_user_agents(self, package, resource, start_date, end_date, callback):
        rows = yield self.db.execute("""
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
        except Exception as e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsBrowserHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        """
            Request all user agents for specific TDT package and resource between start_date and end_date if provided.
            Compute per browser requests percentage and send them back.
        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = yield self.db.execute("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = yield self.db.execute("SELECT * FROM resource WHERE resource_name = %s", str(resource))

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

    @tornado.gen.coroutine
    def parse_user_agents(self, package, resource, start_date, end_date, callback):
        rows = yield self.db.execute("""
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
        except Exception as e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsCoordinateHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        """

        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = yield self.db.execute("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = yield self.db.execute("SELECT * FROM resource WHERE resource_name = %s", str(resource))

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

    @tornado.gen.coroutine
    def parse_coordinates(self, package, resource, start_date, end_date, callback):
        rows = yield self.db.execute("""
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
        except Exception as e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsHitHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def get(self, package, resource, frequency, basicauth_user, basicauth_pass):
        """

        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = yield self.db.execute("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = yield self.db.execute("SELECT * FROM resource WHERE resource_name = %s", str(resource))

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


    @tornado.gen.coroutine
    def parse_hits(self, package, resource, start_date, end_date, frequency, callback):
        d = {'hourly': 'hour', 'daily': 'day', 'weekly': 'week', 'monthly': 'month', 'yearly': 'year'}

        rows = yield self.db.execute("""
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
        except Exception as e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsNotificationsHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.coroutine
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


    @tornado.gen.coroutine
    def parse_notifications(self, start_date, end_date, frequency, callback):
        d = {'hourly': 'hour', 'daily': 'day', 'weekly': 'week', 'monthly': 'month', 'yearly': 'year'}

        rows = yield self.db.execute("""
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
        except Exception as e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsLanguageHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = yield self.db.execute("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = yield self.db.execute("SELECT * FROM resource WHERE resource_name = %s", str(resource))

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

    @tornado.gen.coroutine
    def parse_languages(self, package, resource, start_date, end_date, callback):
        rows = yield self.db.execute("""
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
        except Exception as e:
            logging.error(e)
            callback(data)
        return


@require_basic_auth
class AnalyticsDeviceHandler(BaseHandler):
    """

    """

    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def get(self, package, resource, basicauth_user, basicauth_pass):
        """

        """
        if self.auth(basicauth_user, basicauth_pass):
            start_date = self.get_argument('start_date', 0)
            end_date = self.get_argument('end_date', time.time())
            package_present = yield self.db.execute("SELECT * FROM package WHERE package_name = %s", str(package))
            resource_present = yield self.db.execute("SELECT * FROM resource WHERE resource_name = %s", str(resource))

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

    @tornado.gen.coroutine
    def parse_user_agents(self, package, resource, start_date, end_date, callback):
        rows = yield self.db.execute("""SELECT COUNT(*) as total,
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
        except Exception as e:
            logging.error(e)
            callback(data)
        return