# -*- coding: utf-8 -*-
__author__ = 'quentinkaiser'
import sys, os, time, logging, requests, re, json
from optparse import OptionParser
import multiprocessing
import MySQLdb
import datetime
import calendar
import configparser
from PIL import Image


class WebcamsLoader:
    """
        Utility script that fetch webcam images from belgian providers (Verkeers centrum, Centre Perex, Mobiris).
    """

    webcams_subdirs = ['wallonia', 'flanders', 'brussels']

    def __init__(self, config):
        """
            @param webcams_directory : the directory where the images will be downloaded
            @sleep_time : the time between every reload of images
            @log_filename : pretty obvious, isn't it ?
        """

        self.config = config
        self.webcams_directory = str(self.config['webcams']['download_directory'])
        if os.path.isdir(self.webcams_directory):
            for subdir in self.webcams_subdirs:
                if not os.path.exists("%s%s/" % (self.webcams_directory, subdir)):
                    os.mkdir("%s%s/" % (self.webcams_directory, subdir))
        else:
            raise Exception("Webcams directory don't exist")
            #verify if directories exists or not
        self.sleep_time = int(self.config['webcams']['update_time'])

        #set a custom formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("webcams")
        self.logger.setLevel(logging.INFO)

        default_file = logging.FileHandler("%s-default.log" % (str(self.config['webcams']['log_filename'])), delay=True)
        default_file.setLevel(logging.INFO)
        default_file.setFormatter(formatter)
        self.logger.addHandler(default_file)
        default_file.close()

        error_file = logging.FileHandler("%s-error.log" % (str(self.config['webcams']['log_filename'])), delay=True)
        error_file.setLevel(logging.ERROR)
        error_file.setFormatter(formatter)
        self.logger.addHandler(error_file)
        error_file.close()


    def load_webcams(self, in_queue, out_queue):

        while 1:
            try:
                if not in_queue.empty():
                    item = in_queue.get(True)
                    response = requests.get(
                        item['input_url'],
                        headers=item['headers'])
                    item['status_code'] = response.status_code

                    if 'last-modified' in response.headers:
                        item['last-modified'] = calendar.timegm(datetime.datetime.strptime(
                            response.headers['last-modified'],
                            '%a, %d %b %Y %H:%M:%S %Z'
                        ).utctimetuple())
                    else:
                        item['last-modified'] = None

                    if response.status_code == 200:
                        with open(item['output_url'], "wb") as f:
                            f.write(response.content)
                        img = Image.open(item['output_url'])
                        thumb = img.resize((120, 120), Image.ANTIALIAS)
                        thumb.save("%s_thumb.jpg"%(item['output_url'].replace('.jpg', '')))
                        
                    out_queue.put(item)
            except KeyboardInterrupt:
                self.logger.info('Cleaning up webcams loader...')
                break
            except Exception as e:
                self.logger.exception(e)

    def check_availability(self, in_queue):
        """
            This function read webcam items from in_queue and update their availability depending on the result of
            a call to is_available.
            @param in_queue : a multiprocessing Queue containing webcam items provided by the image_loader
        """
        con = None
        cursor = None

        while 1:
            try:
                con = MySQLdb.connect(
                    str(self.config['mysql']['host']),
                    str(self.config['mysql']['username']),
                    str(self.config['mysql']['password']),
                    str(self.config['mysql']['database']),
                    charset='utf8'
                )
                cursor = con.cursor()

                if not in_queue.empty():
                    item = in_queue.get(True)
                    #we mark the webcam's availability in our database
                    item['available'] = self.is_available(item)
                    query = "UPDATE cameras SET enabled = %d WHERE img = 'http://webcams.beroads.com/%s'" % (
                        item['available'], item['output_url'].replace(self.webcams_directory, ''))
                    cursor = con.cursor()
                    cursor.execute(query)
                    self.logger.info("Item : %s" % item)
                    con.commit()

            except KeyboardInterrupt as e:
                self.logger.info('Cleaning up availability checker...')
                if con:
                    con.rollback()
                if cursor:
                    cursor.close()
                con.close()
                break
            except MySQLdb.Error as e:
                self.logger.exception(e)
                if con:
                    con.rollback()
                    if cursor:
                        cursor.close()
                    con.close()
                break
            except Exception as e:
                self.logger.exception(e)


    def is_available(self, item):
        """
            Analyse loaded images against our sample of unavailable images
            (full blue, full black or unavailable image) with a similarity
            analysis.

            @var image_url : the url of the image that we want to verify
            @return true if the image is available, false if not
        """

        try:
            d = datetime.datetime.utcnow()
            now = calendar.timegm(d.utctimetuple())

            if 'status_code' in item and item['status_code'] != 200:
                return False

            if 'last-modified' in item and item['last-modified'] < now - 60 * 60:
                return False

            with open('%ssamples/unavailable_wallonia.jpg'%self.webcams_directory) as f1, open(item['output_url']) as f2:
                c1 = f1.read()
                c2 = f2.read()
                similarity = float(sum([a == b for a, b in zip(c1, c2)])) / len(c1)
                if similarity > 0.8:
                    return False

            with open('%ssamples/unavailable_flanders.jpg'%self.webcams_directory) as f1, open(item['output_url']) as f2:
                c1 = f1.read()
                c2 = f2.read()
                similarity = float(sum([a == b for a, b in zip(c1, c2)])) / len(c1)
                if similarity > 0.18:
                    return False

            with open('%ssamples/blue.jpg'%self.webcams_directory) as f1, open(item['output_url']) as f2:
                c1 = f1.read()
                c2 = f2.read()
                similarity = float(sum([a == b for a, b in zip(c1, c2)])) / len(c1)
                if similarity > 0.03:
                    return False

            im = Image.open(item['output_url'])
            R, G, B = im.convert('RGB').split()
            r = R.load()
            g = G.load()
            b = B.load()
            w, h = im.size
            black = 0
            # Convert non-black pixels to white
            for i in range(w):
                for j in range(h):
                    if r[i,j] < 10 and g[i, j] < 10 and b[i, j] < 10:
                        black +=1
            if black > 50000:
                return False
        except Exception as e:
            self.logger.exception(e)
        return True

    def scrap_webcams(self, out_queue):

        while 1:
            try:
                timestamp = time.time()-self.sleep_time
                #load webcams from Centre Perex
                for i in range(0, 51):
                    out_queue.put({
                        'input_url': 'http://trafiroutes.wallonie.be/images_uploaded/cameras/image%d.jpg' % (i),
                        'output_url': '%swallonia/camera_%d.jpg' % (self.webcams_directory, i),
                        'headers': {
                            'Referer' : 'http://trafiroutes.wallonie.be',
                            'Accept-Encoding' : 'gzip, deflate',
                            'If-Modified-Since' : time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(timestamp)),
                            'If-None-Match' : ''
                        }
                    })
                reg = re.compile(r'src="/camera-images/(\w+\-*\w+.jpg)')
                page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/antwerpen")
                links = reg.findall(page.content)

                for i in range(0, len(links)):
                    out_queue.put({
                        'input_url': 'http://www.verkeerscentrum.be/camera-images/%s' % (links[i]),
                        'output_url': '%sflanders/image_antwerpen_%d.jpg' % (self.webcams_directory, i),
                        'headers': {
                            'Referer' : 'http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/antwerpen',
                            'Accept' : 'image/png,image/*;q=0.8,*/*;q=0.5',
                            'Accept-Encoding' : 'gzip, deflate',
                            'If-Modified-Since' : time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(timestamp))
                        }
                    })

                page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/gent")
                links = reg.findall(page.content)

                for i in range(0, len(links)):
                    out_queue.put({
                        'input_url': 'http://www.verkeerscentrum.be/camera-images/%s' % (links[i]),
                        'output_url': '%sflanders/image_gand_%d.jpg' % (self.webcams_directory, i),
                        'headers': {
                            'Referer' : 'http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/gent',
                            'Accept' : 'image/png,image/*;q=0.8,*/*;q=0.5',
                            'Accept-Encoding' : 'gzip, deflate',
                            'If-Modified-Since' : time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(timestamp))
                        }
                    })


                #brussels
                page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/brussel")
                links = reg.findall(page.content)
                for i in range(0, len(links)):
                    out_queue.put({
                        'input_url': 'http://www.verkeerscentrum.be/camera-images/%s' % (links[i]),
                        'output_url': '%sflanders/image_brussel_%d.jpg' % (self.webcams_directory, i),
                        'headers': {
                            'Referer' : 'http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/brussel',
                            'Accept' : 'image/png,image/*;q=0.8,*/*;q=0.5',
                            'Accept-Encoding' : 'gzip, deflate',
                            'If-Modified-Since' : time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(timestamp))
                        }
                    })

                page = requests.get("http://www.bruxellesmobilite.irisnet.be/cameras/json/fr/")
                jsonpage = json.loads(page.content)
                for i in range(0, len(jsonpage['features'])):
                    out_queue.put({
                        'input_url': 'http://www.bruxellesmobilite.irisnet.be%s' % (
                            jsonpage['features'][i]['properties']['src']),
                        'output_url': '%sbrussels/image_ringbxl_%d.jpg' % (self.webcams_directory, i),
                        'headers': {
                            'Accept-Encoding' : 'gzip, deflate',
                            'If-Modified-Since' : time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(timestamp))
                        }
                    })
                time.sleep(self.sleep_time)

            except Exception as e:
                self.logger.exception(e)
            except KeyboardInterrupt as e:
                self.logger.info('Cleaning up webcams scraper...')
                break
    def run(self):
        """
            Simple batch processing of pictures that we have
        """
        queues = [multiprocessing.Queue() for i in range(2)]
        workers = [None for i in range(3)]

        workers[0] = multiprocessing.Process(name='webcams_scraper',
            target=self.scrap_webcams,
            args=(queues[0],)
        )

        workers[1] = multiprocessing.Process(name='webcams_loader',
            target=self.load_webcams,
            args=(queues[0], queues[1],)
        )

        workers[2] = multiprocessing.Process(name='availability_checker',
            target=self.check_availability,
            args=(queues[1],)
        )

        for worker in workers:
            worker.start()
        try:
            for worker in workers:
                worker.join()
        except KeyboardInterrupt as e:
            for worker in workers:
                worker.join()
            self.logger.info('done !')
            return
        except Exception as e:
            self.logger.error(e)



if __name__ == "__main__":
    
    parser = OptionParser()
    parser.add_option("-c", "--config", type="string", default="config.ini", help="configuration file")
    (options, args) = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(options.config)

    webcams_loader = WebcamsLoader(config)
    webcams_loader.run()
