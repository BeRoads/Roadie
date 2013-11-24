import sys, os, time, logging, requests, re, json
from optparse import OptionParser
import multiprocessing
import MySQLdb

class WebcamsLoader:
    """
        Utility script that fetch webcam images from belgian providers (Verkeers centrum, Centre Perex, Mobiris).
    """

    webcams_subdirs = ['wallonia', 'flanders', 'brussels']

    def __init__(self, webcams_directory, sleep_time, log_filename='/var/log/beroads/webcams_loader'):
        """
            @param webcams_directory : the directory where the images will be downloaded
            @sleep_time : the time between every reload of images
            @log_filename : pretty obvious, isn't it ?
        """

        self.webcams_directory = webcams_directory
        if os.path.isdir(self.webcams_directory):
            for subdir in self.webcams_subdirs:
                if not os.path.exists("%s%s/"%(self.webcams_directory, subdir)):
                    os.mkdir("%s%s/"%(self.webcams_directory, subdir))
        else:
            raise Exception("Webcams directory don't exist")
        #verify if directories exists or not
        self.sleep_time = sleep_time

        #set a custom formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("webcams")
        self.logger.setLevel(logging.INFO)

        default_file = logging.FileHandler("%s-default.log"%(log_filename), delay=True)
        default_file.setLevel(logging.INFO)
        default_file.setFormatter(formatter)
        self.logger.addHandler(default_file)
        default_file.close()

        error_file = logging.FileHandler("%s-error.log"%(log_filename), delay=True)
        error_file.setLevel(logging.ERROR)
        error_file.setFormatter(formatter)
        self.logger.addHandler(error_file)
        error_file.close()


    def load_webcams(self, in_queue, out_queue):

        try:
            again = True
            while again:
                if not in_queue.empty():
                    item = in_queue.get(True)
                    if item is None:
                        again = False
                        out_queue.put(None)
                    else:
                        input_file = requests.get(item['input_url'], headers={"Referer": item['referer']})
                        with open(item['output_url'], "wb") as f:
                            f.write(input_file.content)
                        out_queue.put(item)
        except Exception as e:
            self.logger.exception(e)
        except KeyboardInterrupt as e:
            sys.exit(0)

    def check_availability(self, in_queue, out_queue):
        """
            This function read webcam items from in_queue and update their availability depending on the result of
            a call to is_available.
            @param in_queue : a multiprocessing Queue containing webcam items provided by the image_loader
        """
        con = None
        cursor = None
        try:
            con = MySQLdb.connect('localhost', 'root', 'my8na6xe', 'beroads', charset='utf8')
            cursor = con.cursor()
            again = True
            while again:
                if not in_queue.empty():
                    item = in_queue.get(True)
                    if item is None:
                        again = False
                    else:
                        #we mark the webcam's availability in our database
                        item['available'] = self.is_available(item['output_url'])
                        query = "UPDATE cameras SET enabled = %d WHERE img = 'http://webcams.beroads.com/%s'"%(
                            item['available'], item['output_url'].replace(self.webcams_directory, ''))
                        cursor = con.cursor()
                        cursor.execute(query)
                        self.logger.info("Item : %s"%item)
                    out_queue.put(item)

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


    def is_available(self, image_url):
        """
            Analyse loaded images against our sample of unavailable images
            (full blue, full black or unavailable image) with a similarity
            analysis.

            @var image_url : the url of the image that we want to verify
            @return true if the image is available, false if not
        """
        samples_url = ['webcams/samples/blue.jpg', 'webcams/samples/black.jpg',
                       'webcams/samples/unavailable.jpg']

        try :
            for sample in samples_url:
                # we analyze every sample against the current file
                with open(sample) as f1, open(image_url) as f2:
                    c1 = f1.read()
                    c2 = f2.read()
                    similarity = float(sum([a==b for a,b in zip(c1,c2)]))/len(c1)
                    if similarity == 1:
                        return False
            return True

        except Exception as e:
            self.logger.exception(e)

    def scrap_webcams(self, webcams_urls_queue):
        try:
            #load webcams from Centre Perex
            for i in range(0, 51):
                webcams_urls_queue.put({
                    'input_url' : 'http://trafiroutes.wallonie.be/images_uploaded/cameras/image%d.jpg'%(i),
                    'output_url' : '%swallonia/camera_%d.jpg'%(self.webcams_directory, i),
                    'referer' : "http://trafiroutes.wallonie.be"
                })

            reg = re.compile(r'src="/camera-images/Camera_(\w+\-*\w+.jpg)')
            page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/antwerpen")
            links = reg.findall(page.content)

            for i in range(0, len(links)):
                webcams_urls_queue.put({
                    'input_url' : 'http://www.verkeerscentrum.be/camera-images/Camera_%s'%(links[i]),
                    'output_url' : '%sflanders/image_antwerpen_%d.jpg'%(self.webcams_directory, i),
                    'referer' : ''
                })

            page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/gent")
            links = reg.findall(page.content)

            for i in range(0, len(links)):
                webcams_urls_queue.put({
                    'input_url' : 'http://www.verkeerscentrum.be/camera-images/Camera_%s'%(links[i]),
                    'output_url' : '%sflanders/image_gand_%d.jpg'%(self.webcams_directory, i),
                    'referer' : ''
                })

            #flanders
            page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/lummen")
            links = reg.findall(page.content)

            for i in range(0, len(links)):
                webcams_urls_queue.put({
                    'input_url' : 'http://www.verkeerscentrum.be/camera-images/Camera_%s'%(links[i]),
                    'output_url' : '%sflanders/image_lummen_%d.jpg'%(self.webcams_directory, i),
                    'referer' : ''
                })

            #brussels
            page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/brussel")
            links = reg.findall(page.content)
            for i in range(0, len(links)):
                webcams_urls_queue.put({
                    'input_url' : 'http://www.verkeerscentrum.be/camera-images/Camera_%s'%(links[i]),
                    'output_url' : '%sflanders/image_brussel_%d.jpg'%(self.webcams_directory, i),
                    'referer' : ''
                })

            page = requests.get("http://www.bruxellesmobilite.irisnet.be/cameras/json/fr/")
            jsonpage = json.loads(page.content)
            for i in range(0, len(jsonpage['features'])):
                webcams_urls_queue.put({
                    'input_url' : 'http://www.bruxellesmobilite.irisnet.be%s'%(
                        jsonpage['features'][i]['properties']['src']),
                    'output_url' : '%sbrussels/image_ringbxl_%d.jpg'%(self.webcams_directory, i),
                    'referer' : ''
                })
            webcams_urls_queue.put(None)
        except KeyboardInterrupt as e:
            self.logger.exception(e)
            sys.exit(0)
        except Exception as e:
            self.logger.exception(e)

    def run(self):
        """
            Simple batch processing of pictures that we have
        """

        webcams_queue = multiprocessing.Queue()
        loaded_webcams_queue = multiprocessing.Queue()
        checked_webcams_queue = multiprocessing.Queue()

        webcams_scraper = multiprocessing.Process(name='webcams_scraper',
            target=self.scrap_webcams,
            args=(webcams_queue,)
        )

        webcams_loader = multiprocessing.Process(name='webcams_loader',
            target=self.load_webcams,
            args=(webcams_queue, loaded_webcams_queue)
        )

        availability_checker = multiprocessing.Process(name='availability_checker',
            target=self.check_availability,
            args=(loaded_webcams_queue, checked_webcams_queue)
        )
        webcams_scraper.start()
        webcams_loader.start()
        availability_checker.start()

        try:
            again = True
            while again:
                if not checked_webcams_queue.empty():
                    item = checked_webcams_queue.get(True)
                    if item is None:
                        again = False
            time.sleep(self.sleep_time)
            webcams_scraper.terminate()
            webcams_loader.terminate()
            availability_checker.terminate()
            self.run()
        except Exception as e:
            self.logger.exception(e)
        except KeyboardInterrupt as e:
            sys.exit(0)


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-d", "--dir", type="string", default="webcams/",
        help="write webcams images to directory")
    parser.add_option("-t", "--time", type="int", default=300, help="time between webcams images refresh")
    (options, args) = parser.parse_args()

    while True:
    #this is a trick to be "error resilient", in fact the majority of errors that
    #we got is because our sources are not available or their server are too slow
    #by enabling this we don't stop the process on error and keep running ;-)
        try:
            webcams_loader = WebcamsLoader(options.dir, options.time)
            webcams_loader.run()
        except KeyboardInterrupt as e:
            logging.exception(e)
            sys.exit(0)
        except Exception as e:
            logging.exception(e)
            continue
        break
