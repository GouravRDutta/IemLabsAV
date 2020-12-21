

from iemlav import logger
import time


class PatchLogger(logger.IemlAVLogger):
    """PatchLogger Class."""

    def __init__(self, modulename, debug=False):

        self._PATH = "/etc/iemlav/auto_patch.log"
        # Call the parent class
        logger.IemlAVLogger.__init__(self, modulename, debug)

    def write_data(self, data):

        with open(self._PATH, "a") as f:
            LEGEND = '[' + self.modulename + ']' + ' [' + \
                           str(time.strftime("%Y-%m-%d %H:%M")) + '] '
            message = LEGEND + data + "\n"
            f.write(message)

    def printinfo(self, message):

        # Call the parent method
        super().printinfo(message)
        self.write_data(message)

    def printerror(self, message):

        # Call the parent method
        super().printerror(message)
        self.write_data(message)

    def printwarning(self, message):

        # Call the parent method
        super().printwarning(message)
        self.write_data(message)
