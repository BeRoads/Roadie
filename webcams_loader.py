import sys, time
from signal import SIGTERM

import requests
import logging
import re
import json


class WebcamsLoader:
    """
        Description
    """


    def __init__(self, webcams_directory, log_file_name='/var/log/beroads/webcams_loader'):

        print "Launching BeRoads webcams loader ..."
        #set where the webcams images will be downloaded
        self.webcams_directory = webcams_directory

        #set a custom formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger("webcams")
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

        print "Launched ! "

    def load_image(self, input_url, output_url, referer=''):

        self.logger.info("Fetching webcam image from " + input_url + " to " + output_url)
        if referer != '':
            input_file = requests.get(input_url, headers={"Referer": referer})
        else:
            input_file = requests.get(input_url)
        with open(output_url, "wb") as f:
            f.write(input_file.content)


    def load_webcams(self):

        try:
            self.logger.info("Fetching webcams from trafiroutes.wallonie.be ...")
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


            self.logger.info("Fetching webcams from verkeerscentrum.be ...")
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

            self.logger.info("Fetching webcams from bruxellesmobilite.irisnet.be ...")
            page = requests.get("http://www.bruxellesmobilite.irisnet.be/cameras/json/fr/")
            jsonpage = json.loads(page.content)
            for i in range(0, len(jsonpage['features'])):
                self.load_image('http://www.bruxellesmobilite.irisnet.be' + jsonpage['features'][i]['properties']['src'],
                    self.webcams_directory + 'brussels/image_ringbxl_' + str(i) + '.jpg')

            time.sleep(60)
            self.load_webcams()
        except Exception as e:
            self.logger.exception(e)



if __name__ == "__main__":

    while True:
    #this is a trick to be "error resilient", in fact the majority of errors that
    #we got is because our sources are not available or their server are too slow
    #by enabling this we don't stop the process on error and keep running ;-)
        try:
            webcams_loader = WebcamsLoader("/var/www/vhosts/beroads/public_html/dashboard/webcams/")
            webcams_loader.load_webcams()
        except Exception as e:
            logging.exception(e)
            continue
        break