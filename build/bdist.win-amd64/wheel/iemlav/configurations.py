
import json
import os

from iemlav import logger


class IemlAVConf():
    """Summary.

    Attributes:
        credentials (dict): Description
        integrations (TYPE): Description
        logger (TYPE): Description
        modulename (str): Description
    """

    modulename = "Config"
    credentials = {}
    confpath = "/etc/iemlav/iemlav.conf"

    def __init__(self):
        """Init logger params."""
        self.logger = logger.IemlAVLogger(
            self.modulename
        )
        

    def get_creds(self, args):

        if args.conf:
            self.confpath = args.conf

        self.credentials = self.get_json(self.confpath)
        return self.credentials

    def get_json(self, path):

        try:
            with open(path) as f:
                creds = json.load(f)
                return creds
        except Exception as e:
            self.logger.log(
                "Config file loading errored, " + str(e),
                logtype="error"
            )

    def save_creds(self, data):

        try:
            os.makedirs(os.path.dirname(self.confpath), exist_ok=True)
            with open(self.confpath, 'w') as outfile:
                json.dump(data, outfile)
        except Exception as e:
            self.logger.log(
                "Error in save Config " + str(e),
                logtype="error"
            )
