import logging
import subprocess
from handlers.base import BaseHandler
from handlers.require_basic_auth import require_basic_auth
import tornado.escape

__author__ = 'lionelschinckus'


@require_basic_auth
class DeploymentHandler(BaseHandler):
    """
        Request handler for admin users that allows specific deployment commands.
    """

    def get(self, target, basicauth_user, basicauth_pass):
        if self.auth(basicauth_user, basicauth_pass):
            try:
                message = ""
                if target == 'mobile':
                    logging.info("Deploying mobile application")
                    message = subprocess.check_output('cd `pwd`/Mobile && git pull')
                    message += subprocess.check_output("/usr/bin/Sencha/Cmd/3.1.0.256/sencha app build %s" %
                                                       self.get_argument('deployment_type', 'testing'))
                elif target == 'tdt':
                    logging.info("Deploying TDT server")
                    message = subprocess.check_output('cd `pwd`/The-DataTank && git pull')
                elif target == 'website':
                    logging.info("Deploying website")
                    message = subprocess.check_output('cd `pwd`/Home && git pull')
                else:
                    self.write_error(404)
                logging.info(message)
                data = {
                    "success": 1,
                    "message": message
                }
            except Exception as e:
                data = {
                    "success": 0,
                    "message": str(e)
                }

            self.set_header("Content-Type", "text/json; charset=UTF-8")
            self.write(tornado.escape.json_encode(data))
        else:
            self.write_error(403)