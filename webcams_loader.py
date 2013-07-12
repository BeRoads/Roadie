import sys, os, time, atexit
from signal import SIGTERM

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



class Daemon:
    """
    A generic daemon class.
    Code taken from here : http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/
    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile,'w+').write("%s\n" % pid)

    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            message = "pidfile %s already exist. Daemon already running?\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            message = "pidfile %s does not exist. Daemon not running?\n"
            sys.stderr.write(message % self.pidfile)
            return # not an error in a restart

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)

    def restart(self):
        """
        Restart the daemon
        """
        #let empty the default log file
        open("%s-default.log"%(log_file_name), 'w').close()
        self.stop()
        self.start()

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """


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

