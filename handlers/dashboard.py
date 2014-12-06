import time
from handlers.base import BaseHandler
from handlers.require_basic_auth import require_basic_auth
import requests
from tornado import gen

__author__ = 'lionelschinckus'


@require_basic_auth
class DashboardHandler(BaseHandler):
    # for monitoring purpose
    def head(self, basicauth_user, basicauth_pass):
        if self.auth(basicauth_user, basicauth_pass):
            return
        else:
            self.send_error(403)


    @gen.coroutine
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

            all_packages = yield self.db.execute("SELECT id, package_name FROM package")
            for p_row in all_packages:
                package_id, package_name = p_row
                packages[package_name] = []
                all_ressources = yield self.db.execute("SELECT resource_name FROM resource WHERE package_id = %s", package_id)
                for r_row in all_ressources:
                    packages[package_name].append(str(r_row[0]))

            events_count = []
            for language in ['fr', 'nl', 'de', 'en']:
                event_count = yield self.db.execute("SELECT * FROM trafic WHERE language = \"%s\" AND time >= CURRENT_DATE" % (language))
                events_count.append(len(event_count.fetchone()))

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

            apple_total = sum(len(v) for v in apple_subscribers.values())
            self.render("../templates/index.html", username=basicauth_user, sources=sources,
                        traffic_feed_channels=['fr', 'nl', 'de', 'en'], google_subscribers=google_subscribers,
                        events_count=events_count, apple_subscribers=apple_subscribers, apple_total=apple_total,
                        web_subscribers=web_subscribers,
                        packages=packages)
        else:
            self.send_error(403)