
from daemon import Daemon
import requests
import logging
import re
import json

log_file_name = '/var/log/beroads/webcams_loader'
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("webcams")
logger.setLevel(logging.INFO)

default_file = logging.FileHandler("%s-default.log"%(log_file_name), delay=True)
default_file.setLevel(logging.INFO)
default_file.setFormatter(formatter)
logger.addHandler(default_file)
default_file.close()

error_file = logging.FileHandler("%s-error.log"%(log_file_name), delay=True)
error_file.setLevel(logging.ERROR)
error_file.setFormatter(formatter)

logger.addHandler(error_file)
error_file.close()


class WebcamsLoader(Daemon):


    def run(self):
        self.webcams_directory = "/Applications/MAMP/htdocs/dashboard/webcams/"
        self.load_webcams()

    def load_image(self, input_url, output_url, referer=''):
        try:
            logger.info("Fetching webcam image from " + input_url + " to " + output_url)
            if referer != '':
                inputfile = requests.get(input_url, headers={"Referer": referer})
            else:
                inputfile = requests.get(input_url)
            with open(output_url, "wb") as f:
                f.write(inputfile.content)
        except Exception as e:
            logging.error(e)


    def load_webcams(self):

        try:
            logger.info("Fetching webcams from trafiroutes.wallonie.be ...")
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


            logger.info("Fetching webcams from verkeerscentrum.be ...")
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

            logger.info("Fetching webcams from bruxellesmobilite.irisnet.be ...")
            page = requests.get("http://www.bruxellesmobilite.irisnet.be/cameras/json/fr/")
            jsonpage = json.loads(page.content)
            for i in range(0, len(jsonpage['features'])):
                self.load_image('http://www.bruxellesmobilite.irisnet.be' + jsonpage['features'][i]['properties']['src'],
                    self.webcams_directory + 'brussels/image_ringbxl_' + str(i) + '.jpg')

            time.sleep(60)
            self.load_webcams()
        except Exception as e:
            logger.exception(e)


if __name__ == "__main__":

    daemon = WebcamsLoader('/var/run/beroads_webcams_loader.pid')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)

