import sys, os, time, logging, requests, re, json
from optparse import OptionParser


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


    def load_image(self, input_url, output_url, referer=''):
        """
            Fetch image data from input_url and store it on output_url.
            @param input_url : the remote image url
            @param output_url : the local image url
            @param referer : an http referer. We use it to trick the trafiroute server
        """
        try:
            self.logger.debug("Fetching webcam image from " + input_url + " to " + output_url)
            if referer != '':
                input_file = requests.get(input_url, headers={"Referer": referer})
            else:
                input_file = requests.get(input_url)
            if input_file.status_code == 200:
                with open(output_url, "wb") as f:
                    f.write(input_file.content)
        except KeyboardInterrupt as e:
            self.logger.exception(e)
            sys.exit(0)

    def run(self):
        """
            Simple batch processing of pictures that we have
        """
        try:
            #load webcams from Centre Perex
            for i in range(0, 51):
                self.load_image('http://trafiroutes.wallonie.be/images_uploaded/cameras/image' + str(i) + '.jpg',
                    self.webcams_directory + 'wallonia/camera_' + str(i) + '.jpg',
                    "http://trafiroutes.wallonie.be")

            reg = re.compile(r'src="/camera-images/Camera_(\w+\-*\w+.jpg)')
            page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/antwerpen")
            links = reg.findall(page.content)

            for i in range(0, len(links)):
                self.load_image('http://www.verkeerscentrum.be/camera-images/Camera_' + links[i],
                    self.webcams_directory + 'flanders/image_antwerpen_' + str(i) + '.jpg')


            page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/gent")
            links = reg.findall(page.content)

            for i in range(0, len(links)):
                self.load_image('http://www.verkeerscentrum.be/camera-images/Camera_' + links[i],
                    self.webcams_directory + 'flanders/image_gand_' + str(i) + '.jpg')

            #flanders
            page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/lummen")
            links = reg.findall(page.content)

            for i in range(0, len(links)):
                self.load_image('http://www.verkeerscentrum.be/camera-images/Camera_' + links[i],
                    self.webcams_directory + 'flanders/image_lummen_' + str(i) + '.jpg')

            #brussels
            page = requests.get("http://www.verkeerscentrum.be/verkeersinfo/camerabeelden/brussel")
            links = reg.findall(page.content)
            for i in range(0, len(links)):
                self.load_image('http://www.verkeerscentrum.be/camera-images/Camera_' + links[i],
                    self.webcams_directory + 'flanders/image_brussel_' + str(i) + '.jpg')

            page = requests.get("http://www.bruxellesmobilite.irisnet.be/cameras/json/fr/")
            jsonpage = json.loads(page.content)
            for i in range(0, len(jsonpage['features'])):
                self.load_image('http://www.bruxellesmobilite.irisnet.be' + jsonpage['features'][i]['properties']['src'],
                    self.webcams_directory + 'brussels/image_ringbxl_' + str(i) + '.jpg')


            time.sleep(self.sleep_time)
            self.run()
        except KeyboardInterrupt as e:
            self.logger.exception(e)
            sys.exit(0)
        except Exception as e:
            self.logger.exception(e)



if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option("-d", "--dir", type="string", default="%s/webcams/"%os.getcwd(),
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