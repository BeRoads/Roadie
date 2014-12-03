# -*- coding: utf-8 -*-
__author__ = 'quentinkaiser'
import pymysql
from optparse import OptionParser
import os
import time
import logging
import requests
from requests_oauthlib import OAuth1
import json
import sys
import configparser
from twitter import *

class RoadWatcher:
    """

    """
    def __init__(self, config):
        """

        """
        self.config = config
        self.sleep_time = int(self.config['road_watcher']['update_time'])

        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("traffic")
        self.logger.setLevel(logging.INFO)

        default_file = logging.FileHandler(
            "%s-default.log" % str(self.config['road_watcher']['log_filename']),
            delay=True
        )
        default_file.setLevel(logging.INFO)
        default_file.setFormatter(formatter)
        self.logger.addHandler(default_file)
        default_file.close()

        error_file = logging.FileHandler(
            "%s-error.log" % str(self.config['road_watcher']['log_filename']),
            delay=True
        )
        error_file.setLevel(logging.ERROR)
        error_file.setFormatter(formatter)
        self.logger.addHandler(error_file)
        error_file.close()

        self.twitter_bots = {}
        try:
            for language in ['fr', 'nl', 'en', 'de']:
                Twitter(auth=OAuth(self.config['twitter']['%s_access_token_key'%language],
                                   self.config['twitter']['%s_access_token_secret'%language],
                                   self.config['twitter']['%s_consumer_key'%language],
                                   self.config['twitter']['%s_consumer_secret'%language]
                                  )
                )

        except Exception as e:
            self.logger.exception(e)
            sys.exit(0)
        self.last_fetch_time = int(time.time())

    def run(self):
        """

        """
        for language in ['fr', 'nl', 'en', 'de']:
            events = self.load_traffic(language)
            if len(events):
                self.notify_twitter(language, events)

        self.last_fetch_time = int(time.time())
        time.sleep(self.sleep_time)
        self.run()


    def notify_twitter(self, language, events):
        """

        """
        try:
            for event in events:
                share_url = "http://beroads.com/event/%s" % event['id']
                place_id = None

                payload = {'lat': event['lat'], 'long': event['lng']}
                self.twitter_bots[language].search.tweets(q=payload)

                if r.status_code == 200:
                    result = json.loads(r.content.decode())
                    if len(result['result']['places']):
                        place_id = result['result']['places'][0]['id']
                        self.logger.info("Place id : %s " % place_id)
                else:
                    self.logger.info("Status code is not 200, it is %s",r.status_code)

                status = "%s ... %s" % (
                    event['location'][0:(140 - len(share_url) - 4)], share_url)

                self.logger.info("Publishing status : %s on Twitter..." % status)

                self.twitter_bots[language].statuses.update(status=status,
                    latitude=event['lat'],
                    longitude=event['lng'],
                    place_id=place_id,
                    display_coordinates=True
                )
        except Exception as e:
            self.logger.exception(e)


    def load_traffic(self, language):
        """

        """
        con = None
        cursor = None
        try:
            con = pymysql.connect(
                str(self.config['mysql']['host']),
                str(self.config['mysql']['username']),
                str(self.config['mysql']['password']),
                str(self.config['mysql']['database']),
                charset='utf8'
            )
            cursor = con.cursor(pymysql.cursors.DictCursor)
            cursor.execute(
                "SELECT * FROM trafic WHERE language = '%s' AND insert_time > %d" % (language, self.last_fetch_time))

            return cursor.fetchall()
        except KeyboardInterrupt:
            if con:
                if cursor:
                    cursor.close()
                con.close()
            sys.exit(2)
        except pymysql.Error as e:
            self.logger.exception(e)
            if con:
                if cursor:
                    cursor.close()
                con.close()
            sys.exit(2)
        except Exception as e:
            self.logger.exception(e)
            if con:
                con.close()


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-c", "--config", type="string",default="%s/config.ini" % os.path.dirname(os.path.abspath(__file__)), help="configuration file")
    (options, args) = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(options.config)

    while True:
    #this is a trick to be "error resilient", in fact the majority of errors that
    #we got is because our sources are not available or their server are too slow
    #by enabling this we don't stop the process on error and keep running ;-)
        try:
            road_watcher = RoadWatcher(config)
            logging.info("Running road_watcher...")
            road_watcher.run()
        except KeyboardInterrupt as e:
            logging.exception(e)
            sys.exit(0)
        except Exception as e:
            logging.exception(e)
            continue
        break
