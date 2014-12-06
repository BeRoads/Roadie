import hashlib
from tornado import gen
import tornado.web

__author__ = 'lionelschinckus'


class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        """
            :rtype Pool
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

    @property
    def config(self):
        """

        """
        return self.application.config

    @gen.coroutine
    def auth(self, username, password):
        """

        """
        authenticated = yield self.db.execute("SELECT * FROM user2 WHERE username=%s AND password = %s",
                                      username,
                                      hashlib.sha1(password).hexdigest())
        return authenticated