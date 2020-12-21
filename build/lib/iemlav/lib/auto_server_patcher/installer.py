
import json
import subprocess
from iemlav.lib.auto_server_patcher.patch_logger import PatchLogger
from iemlav.lib.auto_server_patcher import utils


class Installer(object):
    """Installer Class."""

    def __init__(self, debug=False):

        # Initialize logger
        self.logger = PatchLogger(
            __name__,
            debug=debug
        )

        # Command configuraton path
        self._COMMAND_PATH = "iemlav/lib/auto_server_patcher/configs/commands.json"
        # Load configuraton data
        self.config_data = self.open_json(self._COMMAND_PATH)

        # Categorize OS
        self.os_name = utils.categorize_os()
        if self.os_name:
            try:
                self.os_config_data = self.config_data[self.os_name]
            except KeyError:
                self.logger.log(
                    "Could not load OS configuraton data.",
                    logtype="error"
                )
        else:
            self.logger.log(
                "Could not determine OS specific config."
            )

    @staticmethod
    def open_json(path):

        with open(path, "r") as json_data_file:
            data = json.load(json_data_file)
            return data

    @staticmethod
    def excecute_command(command):

        command = command.split(' ')
        process_respose = subprocess.Popen(command,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        output, error = process_respose.communicate()

        if output:
            output = output.decode('utf-8')
        if error:
            error = error.decode('utf-8')

        return output, error

    def install(self):

        for command in self.os_config_data["commands"]:
            self.logger.log(
                "Executing command: " + command,
                logtype="info"
            )
            output, error = self.excecute_command(command)

            if output:
                msg = "Ouput: " + str(output)
                self.logger.log(
                    msg,
                    logtype="info"
                )

            if error:
                msg = "Error: " + str(output)
                self.logger.log(
                    msg,
                    logtype="info"
                )
