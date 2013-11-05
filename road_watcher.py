import twitter
import MySQLdb
from optparse import OptionParser
import time
import logging
import requests
from requests_oauthlib import OAuth1
import json
import sys

class RoadWatcher:
    """

    """

    twitter_keys =  {
        "fr" : {
            "consumer_key" : "lekthlGntaYeyQFkyXCbQ",
            "consumer_secret" : "6uABinIZpR5YGrvFeLS6pp2EyF8dXgJEvzddfhU",
            "access_token_key" : "1890991999-91RGMHrTrCgO8Ll9s91zrJ6XZrakVvlLjnA4pXR",
            "access_token_secret" : "hMhmFWwbUXqON7rwDaVogFm9ZQsO5Zr87VhosxDmg"
        },
        "nl" : {
            "consumer_key" : "gwC5BwkZxXaS6KEzRQRHow",
            "consumer_secret" : "NYHcj5gII0CwrY49FuwjWqpSWHfRRQyQVYJta0SPhQ",
            "access_token_key" : "1890943374-fEke8UGBUsb0L0onbbexXz2RLed04G6uDJLJiWf",
            "access_token_secret" : "I09VORcgGcq7GAyUJPCWL1OhjQtQB3rtZgyEp5PDI"
        },
        "de" : {
            "consumer_key" : "cNX9Fazas6rFyvBZXyEQ",
            "consumer_secret" : "mDcEC5lulc6mXxnBCZI7PppJOhRLY3cu245Mlb00Yh0",
            "access_token_key" : "1890967974-yi8M6gon8L4eqHT4iOqaZopqMjkCTWj50DfRY5o",
            "access_token_secret" : "HGjbpOzZU86k532nx44UD0R9yqliSGKaDf6L61FfKk"
        },
        "en" : {
            "consumer_key" : "9O4HYykiJYRaVe2Gkrduw",
            "consumer_secret" : "JF2Ngwhk8IhINvNL9lQwC6G3bIfvmrfgeW8rOakqq7U",
            "access_token_key" : "1890992048-HTvKluMInxAyl9JcAGuxt4RqsyNvuabK2tJvkHr",
            "access_token_secret" : "7j7HpyjTFzBFuJ3SGXTMK7SfsxHCgIHNc8uAvH2lR0"
        }
    }

    def __init__(self, sleep_time, log_filename="/var/log/beroads/road_watcher.log"):
        """

        """
        self.sleep_time = sleep_time
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("traffic")
        self.logger.setLevel(logging.INFO)

        default_file = logging.FileHandler("%s-default.log"%log_filename, delay=True)
        default_file.setLevel(logging.INFO)
        default_file.setFormatter(formatter)
        self.logger.addHandler(default_file)
        default_file.close()

        error_file = logging.FileHandler("%s-error.log"% log_filename, delay=True)
        error_file.setLevel(logging.ERROR)
        error_file.setFormatter(formatter)
        self.logger.addHandler(error_file)
        error_file.close()

        self.twitter_bots = {}
        try:
            for language in self.twitter_keys:
                self.twitter_bots[language] = twitter.Api(
                    consumer_key=self.twitter_keys[language]['consumer_key'],
                    consumer_secret=self.twitter_keys[language]['consumer_secret'],
                    access_token_key=self.twitter_keys[language]['access_token_key'],
                    access_token_secret=self.twitter_keys[language]['access_token_secret']
                )

                if self.twitter_bots[language].VerifyCredentials() is None:
                    raise Exception("Twitter bot credentials are wroooong ! ")
        except Exception as e:
            self.logger.exception(e)
            sys.exit(0)
        self.last_fetch_time = int(time.time())

    def run(self):
        """

        """
        for language in self.twitter_keys:
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

                share_url = "http://beroads.com/event/%s"%event['id']
                place_id = None

                auth = OAuth1(
                    self.twitter_keys[language]['consumer_key'],
                    self.twitter_keys[language]['consumer_secret'],
                    self.twitter_keys[language]['access_token_key'],
                    self.twitter_keys[language]['access_token_key']
                )

                payload = {'lat' : event['lat'], 'long' : event['lng']}
                r = requests.get('https://api.twitter.com/1.1/geo/search.json', params=payload, auth=auth)

                if r.status_code==200:
                    result = json.loads(r.content)
                    if len(result['result']['places']):
                        place_id = result['result']['places'][0]['id']

                status = "%s ... %s"%(
                    event['location'][0:(140-len(share_url)-4)], share_url)

                self.logger.info("Publishing status : %s on Twitter..."%status)

                self.twitter_bots[language].PostUpdate(status=status,
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
            con = MySQLdb.connect('localhost', 'root', 'cC6GRfysDHyLPH', 'beroads', charset='utf8')
            cursor = con.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT * FROM trafic WHERE language = '%s' AND insert_time > %d"%(language, self.last_fetch_time))

	    return cursor.fetchall()
        except KeyboardInterrupt:
            if con:
                if cursor:
                    cursor.close()
                con.close()
            sys.exit(2)
        except MySQLdb.Error as e:
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
    parser.add_option("-t", "--time", type="int", default=300, help="time between traffic fetching")
    (options, args) = parser.parse_args()

    while True:
    #this is a trick to be "error resilient", in fact the majority of errors that
    #we got is because our sources are not available or their server are too slow
    #by enabling this we don't stop the process on error and keep running ;-)
        try:
            road_watcher = RoadWatcher(options.time)
            road_watcher.run()
        except KeyboardInterrupt as e:
            logging.exception(e)
            sys.exit(0)
        except Exception as e:
            logging.exception(e)
            continue
        break
