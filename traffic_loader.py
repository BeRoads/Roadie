# -*- coding: utf-8 -*-

__author__ = 'quentinkaiser'
import sys, time, signal


import requests
import logging
import re
from lxml import etree
import json
import math
import hashlib
import memcache
import re
import datetime
from BeautifulSoup import BeautifulSoup
import htmlentitydefs
import multiprocessing
from multiprocessing import Queue
import MySQLdb
import time
from optparse import OptionParser


#TODO : APNS code checking
#TODO : dashboard - logging of push notifications in mysql
#TODO : dashboard - polishing the interface
#TODO : deploy & profit !

##
# Removes HTML or XML character references and entities from a text string.
#
# @param text The HTML (or XML) source text.
# @return The plain text, as a Unicode string, if necessary.

def unescape(text):
    def fixup(m):
        text = m.group(0)
        if text[:2] == "&#":
            # character reference
            try:
                if text[:3] == "&#x":
                    return unichr(int(text[3:-1], 16))
                else:
                    return unichr(int(text[2:-1]))
            except ValueError:
                pass
        else:
            # named entity
            try:
                text = unichr(htmlentitydefs.name2codepoint[text[1:-1]])
            except KeyError:
                pass
        return text # leave as is
    return re.sub("&#?\w+;", fixup, text)

class Tools:
    """

    """

    def __init__(self):
        self.a=6378388.0
        self.f=1/297.0
        self.x0=150000.013
        self.y0=5400088.438
        self.e = math.sqrt(2.0*self.f-self.f*self.f)
        self.p0=math.radians(90.0)
        self.p1=math.radians(49.83333367)
        self.p2=math.radians(51.166664006)
        self.l0=math.radians(4.367158666)
        self.m1= math.cos(self.p1)/math.sqrt(1.0-self.e*self.e*math.sin(self.p1)*math.sin(self.p1))
        self.m2= math.cos(self.p2)/math.sqrt(1.0-self.e*self.e*math.sin(self.p2)*math.sin(self.p2))
        self.t1 = math.tan(math.pi/4.0-self.p1/2.0)/math.pow((1.0-self.e*math.sin(self.p1))/(1.0+self.e*math.sin(self.p1)), self.e/2.0)
        self.t2 = math.tan(math.pi/4.0-self.p2/2.0)/math.pow((1.0-self.e*math.sin(self.p2))/(1.0+self.e*math.sin(self.p2)), self.e/2.0)
        self.t0 = math.tan(math.pi/4.0-self.p0/2.0)/math.pow((1.0-self.e*math.sin(self.p0))/(1.0+self.e*math.sin(self.p0)), self.e/2.0)
        self.n= (math.log(self.m1)-math.log(self.m2))/(math.log(self.t1)-math.log(self.t2))
        self.g = self.m1/(self.n*math.pow(self.t1,self.n))
        self.r0=self.a*self.g*math.pow(self.t0,self.n)

    def lambert_to_WGS84(self, x, y):
        """

        """
        r = math.sqrt((x-self.x0)*(x-self.x0) + (self.r0-(y-self.y0))*(self.r0-(y-self.y0)))
        t = math.pow((r/(self.a*self.g)),1/self.n)
        theta = math.atan((x-self.x0)/(self.r0-y+self.y0))
        lam = (theta/self.n)+self.l0
        phi = math.pi/2.0 - 2.0 * math.atan(t) #this is a wild guess
        #we're going to make this guess better on each iteration
        for i in range(0,10):
            phi = math.pi/2 - 2 * math.atan(t * math.pow((1.0-self.e*math.sin(phi))/(1.0+self.e*math.sin(phi)), self.e/2.0))

        return {"latitude" : math.degrees(phi), "longitude" : math.degrees(lam)}


    def WGS84_to_lambert(self, phi, lam):
        """

        """
        phi = math.radians(phi)
        lam = math.radians(lam)
        t = math.tan(math.pi/4-phi/2)/math.pow((1-self.e*math.sin(phi))/(1+self.e*math.sin(phi)), self.e/2)
        r = self.a * self.g * math.pow(t,self.n)
        theta = self.n*(lam - self.l0)
        x = self.x0+r*math.sin(theta)
        y = self.y0+self.r0-r*math.cos(theta)

        return {"lam" : x, "phi" : y}


class Geocoder:
    """
        /* Copyright (C) 2011 by iRail vzw/asbl */
        This file is part of iWay.

        iWay is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        iWay is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with iWay.  If not, see <http://www.gnu.org/licenses/>.

        http://www.beroads.com

        Source available at http://github.com/QKaiser/IWay
        */

        /**
        * All functionnalities about geolocation (get coordinates from API like
        * GMap, Bing or OSM; compute distance between coordinates).
        */
    """

    max_over_query_retry = 5
    over_query_retry = 0

    keywords = [
            {
            "fr" : "à",
            "en" : "in",
            "nl" : "in",
            "de" : "in"
        },
            {
            "fr" : "vers",
            "en" : "to",
            "nl" : "naar",
            "de" : "nach"
        },
            {
            "fr" : "la",
            "en" : "the",
            "nl" : "de",
            "de" : "der"
        },
            {
            "fr" : "à hauteur de",
            "en" : "ter hoogte van",
            "nl" : "ter hoogte van",
            "de" : "ter hoogte van"
        },
            {
            "fr" : "en direction de",
            "en" : "richting",
            "nl" : "richting",
            "de" : "richting"
        }
    ]



    def __init__(self):

        log_file_name = "/var/log/beroads/geocoding"

        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("geocoder")
        self.logger.setLevel(logging.INFO)

        default_file = logging.FileHandler("%s-default.log"%(log_file_name), delay=False)
        default_file.setLevel(logging.INFO)
        default_file.setFormatter(formatter)
        self.logger.addHandler(default_file)
        default_file.close()

        error_file = logging.FileHandler("%s-error.log"%(log_file_name), delay=False)
        error_file.setLevel(logging.ERROR)
        error_file.setFormatter(formatter)
        self.logger.addHandler(error_file)
        error_file.close()

    def geocode(self, address, tool = "osm"):
        """
            Geocode an address with online tools such as Google Maps, OpenStreetMap (Nominatim) or Bing Maps
            @param $address : the address to be geocoded
            @param $tool : the online tool used to geocode (eg. gmap, osm, bing)
            @return an array of decimal coordinates ("lat"=>0, "lng"=>0)

        """
        try:
            coordinates = {"lng" : 0, "lat" : 0}

            if address is None or address == "":
                return coordinates

            key = str(address.split(" ")[0])
            c = memcache.Client(['127.0.0.1:11211'], debug=False)
            coordinates = c.get(key)
            if coordinates is not None:
                return coordinates
            else:
                #gmap api geocoding tool
                if tool=="gmap":
                    address += ", Belgium"
                    request_url = "https://maps.googleapis.com/maps/api/geocode/json?address=%s&sensor=false"%address
                    response = requests.get(request_url)
                    time.sleep(1)
                    content = json.loads(response.content)
                    status = content['status']
                    self.logger.info("%s-> %s : %s \n"%(address, request_url, status))
                    #successful geocode
                    if status == "OK":
                        self.over_query_retry = 0
                        coordinates = {
                            "lng": content['results'][0]['geometry']['location']['lng'],
                            "lat" : content['results'][0]['geometry']['location']['lat']
                        }
                    #too much requests, gmap server can't handle it
                    elif status == "OVER_QUERY_LIMIT":
                        if self.over_query_retry < self.max_over_query_retry:
                            self.over_query_retry+=1
                            coordinates = self.geocode(address, "osm")
                        else:
                            return {"lng" : 0, "lat" : 0}
                    else:
                        return {"lng" : 0, "lat" : 0}


                #openstreetmap geocoding tool (Nominatim)
                elif tool == "osm":

                    request_url = "http://nominatim.openstreetmap.org/search/be/%s/"\
                    "?format=json&addressdetails=0&limit=1&countrycodes=be"%address
                    response = requests.get(request_url)
                    content = json.loads(response.content)
                    self.logger.info("%s-> %s : %s \n"%(address, request_url, 1 if len(content) else 0))

                    if not len(content):
                        if self.over_query_retry < self.max_over_query_retry:
                            self.over_query_retry+=1
                            coordinates = self.geocode(address, "gmap")
                        else:
                            return {"lng" : 0, "lat" : 0}
                    else:
                        self.over_query_retry=0
                        place = content[0]
                        coordinates = {
                            "lng" : place['lon'],
                            "lat" : place['lat']
                        }

                else:
                    raise Exception("Wrong tool parameter, please retry.")

                c.set(key, coordinates)
                return coordinates
        except Exception as e:
            self.logger.exception(e)
            return {"lng" : 0, "lat" : 0}



    def geocodeData(self, data, region, language):
        """
            Extract relevant information from a string depending on its source. Relevant information
            is mainly town, street, area or highways to be geocoded later.

            @param data : a string to be analyzed
            @param region : the source region of $data
            @param language : the language in which $data is written
            @return an array of decimal coordinates ("lat"=>0, "lng"=>0)
        """

        if region=="federal" or region == "flanders":
            match = re.findall(r"(.*?) %s (-*(\w+)-*)+"%self.keywords[0][language], data)

            if(len(match)==1 and len(match[0])>=2):
                data = match[0][1]
            else:
                match = re.findall("(.*?) -> (\w*)", data)
                if(len(match)==1 and len(match[0])==2):
                    data = match[0][1]
                else:
                    match = re.findall("(\w*) %s (\w*)"%self.keywords[1][language] , data)
                    if len(match)==1 and len(match[0])==2:
                        data = match[0][1]
        else:
            raise Exception("Wrong source parameter, please retry.")

        return self.geocode(data)

class TrafficLoader:
    """
        A utility script that fetch trafic info from belgian providers and store it into a database for late use.
    """

    urls = {

        'wallonia': {
            'fr' : 'http://trafiroutes.wallonie.be/trafiroutes/Evenements_FR.rss',
            'nl' : 'http://trafiroutes.wallonie.be/trafiroutes/Evenements_NL.rss',
            'de': 'http://trafiroutes.wallonie.be/trafiroutes/Evenements_DE.rss',
            'en' : 'http://trafiroutes.wallonie.be/trafiroutes/Evenements_EN.rss',
        },
        'flanders' : {
            'fr' : 'http://www.verkeerscentrum.be/rss/1%7C100%7C101%7C102%7C103%7C2%7C4%7C5-INC%7CLOS%7CINF%7CPEVT.xml',
            'nl' : 'http://www.verkeerscentrum.be/rss/1%7C100%7C101%7C102%7C103%7C2%7C4%7C5-INC%7CLOS%7CINF%7CPEVT.xml',
            'de' : 'http://www.verkeerscentrum.be/rss/1%7C100%7C101%7C102%7C103%7C2%7C4%7C5-INC%7CLOS%7CINF%7CPEVT.xml',
            'en' : 'http://www.verkeerscentrum.be/rss/1%7C100%7C101%7C102%7C103%7C2%7C4%7C5-INC%7CLOS%7CINF%7CPEVT.xml'
        },
        'brussels' : {
            'fr': 'http://www.bruxellesmobilite.irisnet.be/static/mobiris_files/fr/alerts.json',
            'nl' : 'http://www.bruxellesmobilite.irisnet.be/static/mobiris_files/nl/alerts.json',
            'de' : 'http://www.bruxellesmobilite.irisnet.be/static/mobiris_files/nl/alerts.json',
            'en' : 'http://www.bruxellesmobilite.irisnet.be/static/mobiris_files/nl/alerts.json'
        },
        'federal' : {
            'fr': 'http://www.inforoutes.be',
            'nl' : 'http://www.wegeninfo.be/',
            'de' : 'http://www.wegeninfo.be/',
            'en' : 'http://www.wegeninfo.be/'
        }
    }


    def __init__(self, sleep_time, log_file_name='/var/log/beroads/traffic_loader'):

        self.sleep_time = sleep_time
        #set a custom formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("traffic")
        self.logger.setLevel(logging.INFO)

        default_file = logging.FileHandler("%s-default.log"%(log_file_name), delay=True)
        default_file.setLevel(logging.INFO)
        default_file.setFormatter(formatter)
        self.logger.addHandler(default_file)
        default_file.close()

        error_file = logging.FileHandler("%s-error.log"%(log_file_name), delay=True)
        error_file.setLevel(logging.ERROR)
        error_file.setFormatter(formatter)
        self.logger.addHandler(error_file)
        error_file.close()


    def run(self):
        """
            This is the main process.
            The others are :
                sql_storing : a process that reads trafic event items from traffic_events_queue and store them in
                an MySQL database
                traffic_loader : a process that load data from web pages stored in self.urls and send out the content
                to traffic_raw_data_queue
                parsing_processes : 4 languages x 4 region (16) processes that parse data from the traffic_raw_data_queue
                and send out trafic event items (python dict) to traffic_events_queue which is read by sql_storing

            Once the processes are started, the script wait for X seconds before terminating each process and relaunching
            the script to update values.
        """

        traffic_raw_data_queue = multiprocessing.Queue()
        traffic_events_queue = multiprocessing.Queue()

        sql_storing = multiprocessing.Process(name='data_storing',
            target=self.store_traffic,
            args=(traffic_events_queue,)
        )
        sql_storing.start()

        traffic_loader = multiprocessing.Process(name='traffic_loader',
            target=self.load_traffic,
            args=(traffic_raw_data_queue,)
        )
        traffic_loader.start()

        parsing_processes = []

        try:
            again = True
            while again:
                if not traffic_raw_data_queue.empty():
                    raw_data = traffic_raw_data_queue.get(True, 0.5)
                    if raw_data is None:
                        again = False
                    else:
                        self.logger.debug("Got data from %s - %s"%(raw_data['region'], raw_data['language']))
                        parsing_processes.append(
                            multiprocessing.Process(name='%s - %s'%(raw_data['region'], raw_data['language']),
                            target=self.parse_traffic,
                            args=(raw_data, traffic_events_queue,)
                        ))
                        parsing_processes[len(parsing_processes)-1].start()
            time.sleep(self.sleep_time)
            for p in parsing_processes:
                p.terminate()
            traffic_loader.terminate()
            sql_storing.terminate()
            self.run()
        except Exception as e:
            self.logger.exception(e)
        except KeyboardInterrupt as e:
            sys.exit(0)



    def load_traffic(self, out_queue):
        """
            This function load data from web pages and send them out in out_queue which is read by the main process.
            @param out_queue : a multiprocessing Queue used to send out raw data from web pages
            @return /
        """

        try:
            for region in self.urls:
                for language in self.urls[region]:
                    r = requests.get(self.urls[region][language])
                    if r.status_code != 200:
                        raise Exception("Content unavailable on %s"%self.urls[region][language])
                    out_queue.put({'region' : region, 'language' : language, 'content' : r.content})
                    self.logger.info("Loaded traffic from %s in %s on %s"%
                                     (region, language, self.urls[region][language]))

        except KeyboardInterrupt as e:
            out_queue.put(None)
        except Exception as e:
            logging.exception(e)
            out_queue.put({'region' : region, 'language' : language, 'content' : None})
        finally:
            out_queue.put(None)


    def store_traffic(self, in_queue):
        """
            This function read trafic event items from in_queue and store them in a MySQL database if they are not
            already stored in it (checked with a custom hash, see below).
            @param in_queue : a multiprocessing Queue containing trafic event items provided by the trafic parsers
        """
        con = None
        cursor = None
        try:
            con = MySQLdb.connect('localhost', 'root', 'cC6GRfysDHyLPH', 'beroads', charset='utf8')
            cursor = con.cursor()
	    cursor.execute("UPDATE trafic SET active = 0 WHERE 1")
	    counter = 0
            while counter < 16:
                if not in_queue.empty():
                    item = in_queue.get(True, 0.5)
                    if item is None:
                        counter+=1
                    else:
                        self.logger.info("Got item %s"%item)
                        #we do this kind of hashing because we don't have a real time value for brussels events so everytime
                        #we load them we could have different hashes for the same event if we hash the time
                        item['hash'] = hashlib.md5("%s+%s+%s+%s+%s+%s+%s+%s"%
                                                   (item['region'], item['language'], item['location'], item['message'],
                                                    item['category'], item['source'], item['lat'], item['lng'])).hexdigest()
                        cursor = con.cursor()
                        cursor.execute("SELECT * FROM trafic WHERE hash = '%s'"%item['hash'])
                        row = cursor.fetchone()
                        if row is None:
                            query = "INSERT INTO trafic \
                                                    (region, language, location, message, category, source, hash, lat, lng, time, insert_time, active) \
                                                    VALUES \
                                                     (\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", %f, %f, %d, %d, 1)"%(
                                con.escape_string(item['region']),
                                con.escape_string(item['language']),
                                con.escape_string(item['location']),
                                con.escape_string(item['message']),
                                con.escape_string(item['category']),
                                con.escape_string(item['source']),
                                con.escape_string(item['hash']),
                                float(item['lat']),
                                float(item['lng']),
                                time.mktime(item['time'].timetuple()),
                                int(time.time())
                            )
                            cursor.execute(query)
                        else:
			     cursor.execute("UPDATE trafic SET active = 1 WHERE hash = '%s'"%item['hash'])
			cursor.close()
            con.commit()
            con.close()
        except KeyboardInterrupt as e:
            if con:
                con.rollback()
                if cursor:
                    cursor.close()
                con.close()
            sys.exit(2)
        except MySQLdb.Error as e:
            self.logger.exception(e)
            if con:
                con.rollback()
                if cursor:
                    cursor.close()
                con.close()
            sys.exit(2)
        except Exception as e:
            self.logger.exception(e)
            if con:
                con.close()


    def parse_traffic(self, raw_data, out_queue):
        """
            This function read website's raw content from the raw_data_queue, parse it and send out trafic items to
            out_queue.
            @param raw_data : a multiprocessing Queue containing website's raw content provided by trafic_loader.
            @param out_queue : a multiprocessing Queue where we put trafic items that we have parsed.
        """

        try:
            geocoder = Geocoder()
            region = raw_data['region']
            language = raw_data['language']
            traffic = raw_data['content']

            if traffic is not None:
                if region == "wallonia":
                    categories = {"CHANIV1":"others","CHANIV2":"works","CHANIV3":"works","INCNIV1":"events","INCNIV2":"events",
                        "INCNIV3":"events"}
                    try:
                        url = 'http://trafiroutes.wallonie.be/trafiroutes/Rest/Resources/Evenements/All/%s'%language.upper()
                        page = requests.get(url)
                        if page.status_code != 200:
                            raise Exception("Content unavailable on %s"%url)
                        data = json.loads(page.content)
                        soup = BeautifulSoup(traffic)
                        items = soup.findAll('item')
                        for item in items:

                            node = {
                                'region' : region,
                                'language' : language,
                                'category' : '',
                                'source' : 'Trafiroutes',
                                'time' : self.parse_time(region, item.pubdate.string),
                                'message' : item.description.string,
                                'location' : item.title.string,
                            }

                            evt = item.guid.string.replace('http://trafiroutes.wallonie.be/trafiroutes/maptempsreel/?v=EVT', '')
                            for x in data:
                                if x['idEvenement']== evt:
                                    node['lat'] = x['lat']
                                    node['lng'] = x['lon']
                                    node['category'] = categories[x['nomIcone']]
                            out_queue.put(node)
                        out_queue.put(None)
                    except Exception as e:
                        self.logger.exception(e)

                elif region == "flanders":
                    categories = {
                        "ongevallen" : "accident",
                        "files" : "traffic jam",
                        "wegeninfo" : "info",
                        "werkzaamheden" : "works"
                    }
                    try:
                        soup = BeautifulSoup(traffic)

                        items = soup.findAll('item')
                        for item in items:

                            category = categories[item.category.string]
                            location = unescape(item.title.string)
                            coordinates = geocoder.geocodeData(location, region, language)

                            node = {
                                'region' : region,
                                'language' : language,
                                'category' : category,
                                'location' : location,
                                'message' :  unescape(item.description.string),
                                'time' : self.parse_time(region, item.pubdate.string),
                                'source' : "Verkeerscentrum",
                                'lat' : coordinates['lat'],
                                'lng' : coordinates['lng']
                            }
                            out_queue.put(node)
                        out_queue.put(None)
                    except Exception as e:
                        self.logger.exception(e)


                elif region == "brussels":
                    import time
                    try:
                        json_tab = json.loads(traffic)
                        t = Tools()
                        for element in json_tab['features']:

                            coordinates = element['geometry']['coordinates']

                            #TODO : fix coordinates translation
                            coordinates = t.lambert_to_WGS84(coordinates[0], coordinates[1])

                            item = {
                                'region' : region,
                                'language' : language,
                                'category' : element['properties']['category'].lower(),
                                'source' : 'Mobiris',
                                'time' : datetime.datetime.now(),
                                'message' : element['properties']['cause'],
                                'location' : unescape(element['properties']['street_name']),
                                'lat' : coordinates['latitude'],
                                'lng' : coordinates['longitude']
                            }
                            out_queue.put(item)
                        out_queue.put(None)

                    except Exception as e:
                        self.logger.exception(e)

                elif region == "federal":
                    try:
                        soup = BeautifulSoup(traffic)
                        locations = soup.findAll(name='td', attrs={'class':'textehome', 'valign':'middle', 'width':'475'})

                        dates = soup.findAll(name='td', attrs={'class':'textehome', 'valign':'middle', 'width':'90'})
                        messages = soup.findAll(name='font', attrs={'class':'textehome'})
                        locations.pop(0)
                        dates.pop(0)

                        for message, location, date in zip(messages, locations, dates):

                            message = unescape(re.sub("\s+" , " ", re.sub(r'[\t\n\r]', ' ', re.sub('<[^>]*>', '', str(message)))))
                            location = unescape(re.sub('<[^>]*>', '', str(location)))
                            if "FILES - TRAVAUX" not in location and "FILES - WERKEN" not in location:
                                coordinates = geocoder.geocodeData(location, region, language)
                                item = {
                                    'region' : region,
                                    'language' : language,
                                    'message' : message.split(':')[2],
                                    'location' : location,
                                    'source' : message.split(':')[1].replace(" meldt", "").replace(" signale", ""),
                                    'time' : self.parse_time(region, re.sub('<[^>]*>', '', str(date))),
                                    'lat' : coordinates['lat'],
                                    'lng' : coordinates['lng']
                                }

                                #TODO : dutch ?
                                if "travaux" in message or "chantier" in message:
                                    item['category'] = "works"
                                elif "accident" in message or "incident" in message:
                                    item['category'] = "events"
                                else:
                                    item['category'] = "other"
                                out_queue.put(item)
                        out_queue.put(None)

                    except Exception as e:
                        self.logger.exception(e)

                else:
                    raise Exception("Wrong region parameter !")

        except KeyboardInterrupt as e:
            out_queue.put(None)



    def parse_time(self, region, content):
        """
            A simple time parser depending on region and language.
        """

        months = {"jan" : 1, "feb" : 2, "mar" : 3, "apr" : 4, "may" : 5, "jun" : 6, "jul" : 7, "aug" : 8, "sept" : 9,
                  "oct" : 10, "nov" : 11, "dec" : 12}

        if region == "wallonia":
            #sam., 10 sept. 2011 23:57:43 +0200
            match = re.findall(r'(\w+), (\d+) (\w+) (\d+) ((\d\d):(\d\d):(\d\d)) \+(\d+)',content)

            return datetime.datetime(int(match[0][3]), months[str(match[0][2]).lower()], int(match[0][1]), int(match[0][5]),
                int(match[0][6]), int(match[0][7]))

        elif region == "flanders":

            match = re.findall(r"([0-2][0-9]):([0-5][0-9])<br>(\d\d)-(\d\d)-(\d\d)", content)
            if len(match)==6:
                return datetime.date(match[4], months[match[3]], match[2], match[1], match[0])
            else:
                match = re.findall(r"([0-2][0-9]):([0-5][0-9])", content)
                today = datetime.date.today()
                h = datetime.time(int(match[0][0]), int(match[0][1]))
                return datetime.datetime(today.year, today.month, today.day, h.hour, h.minute)

        elif region == "federal":
            match = re.findall("(\d\d\d\d)-(\d\d)-(\d\d) ([0-2][0-9]):([0-5][0-9]):([0-5][0-9])", content)
            return datetime.datetime(int(match[0][0]),int(match[0][1]),int(match[0][2]),int(match[0][3]),
                                        int(match[0][4]),int(match[0][5]))
        else:
            return time.time()



if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-t", "--time", type="int", default=900, help="time between trafic refresh")
    (options, args) = parser.parse_args()

    while True:
    #this is a trick to be "error resilient", in fact the majority of errors that
    #we got is because our sources are not available or their server are too slow
    #by enabling this we don't stop the process on error and keep running ;-)
        try:
            traffic_loader = TrafficLoader(options.time)
            traffic_loader.run()
        except Exception as e:
            logging.exception(e)
            continue
        break
