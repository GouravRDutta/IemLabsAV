
import struct

import sys
import time
import threading

from iemlav import configurations
from iemlav import logger
from iemlav.lib.firewall import iemlAVFirewall
from iemlav.args.arguments import get_args
from iemlav.args.args_helper import ArgsHelper
from iemlav.lib.firewall.utils import setup_logger
from iemlav.lib.ids import iemlAVIDS
from iemlav.lib.log_monitor.system_log import engine
from iemlav.lib.log_monitor.server_log.iemlAVServerLog import IemlAVServerLog
from iemlav.lib.auto_server_patcher.iemlAVServerPatcher import IemlAVAutoServerPatcher
from iemlav.lib.antivirus.iemlAVAntiVirus import IemlAVAntiVirus
pynput_status = True

try:
    from pynput import mouse
except Exception as e:
    pynput_status = False


class IemlAV(object):
    """IemlAV Class."""

    alert_count = 1

    def __init__(self):

        modulename = 'Core'
        self.cred = {}
        args = get_args()
        argsHelper = ArgsHelper(args)
        args_dict = argsHelper.check_args()
        credentials = configurations.IemlAVConf()

        self.cred = args_dict['cred']
        self.cred_provided = args_dict['cred_provided']
        self.firewall_provided = args_dict['firewall_provided']
        self.ids_provided = args_dict['ids_provided']
        self.system_log_provided = args_dict['system_log_provided']
        self.server_log_provided = args_dict['server_log_provided']
        self.auto_server_patcher_provided = args_dict['auto_server_patcher_provided']
        self.antivirus_provided = args_dict['antivirus_provided']
        

        # Initialize logger
        self.logger = logger.IemlAVLogger(
            modulename,
            self.cred['debug']
        )

        # Setup logger for utils
        setup_logger(debug=self.cred['debug'])

        if self.cred_provided:
            credentials.save_creds(self.cred)
        else:
            self.cred = credentials.get_creds(args)

           
            try:
                if self.cred['firewall']:
                   
                    self.firewall_provided = True
                    self.cred_provided = True
            except KeyError:
                self.logger.log(
                    "Firewall configuraton parameter not set.",
                    logtype="error"
                )

            
            try:
                if self.cred['ids']:
                    self.ids_provided = True
                    self.cred_provided = True
            except KeyError:
                self.logger.log(
                    "Intrusion Detection System (IDS) not set.",
                    logtype="error"
                )

            try:
                 if self.cred['server_log']:
                     self.server_log_provided = True
                     self.cred_provided = True
            except KeyError:
                self.logger.log(
                    "Server Log configuraton parameter not set.",
                    logtype="error"
                )

            try:
                if self.cred['auto_server_patcher']:
                    self.auto_server_patcher_provided = True
                    self.cred_provided = True
            except KeyError:
                self.logger.log(
                    "Auto server patcher configuraton not set.",
                    logtype="error"
                )

            
            try:
                if self.cred['antivirus_provided']:
                    self.antivirus_provided = True
                    self.cred_provided = True
            except KeyError:
                self.logger.log(
                    "AntiVirus configuraton not set.",
                    logtype="error"
                )


        if not self.cred:
            self.logger.log(
                "Configuration not found.",
                logtype="error"
            )
            sys.exit(0)

        self.logger.log(
            "Welcome to IemlAV..!! Initializing System",
            logtype="info"
        )

        

        if self.firewall_provided:
            try:
                if self.cred['firewall']:
                    firewallObj = iemlAVFirewall.IemlAVFirewall(cred=self.cred,
                                                                      debug=self.cred['debug'])
                    firewallObj.start_firewall()
            except KeyError:
                self.logger.log(
                    "Firewall configuration parameter not configured.",
                    logtype="error"
                )

        

        if self.ids_provided:
            try:
                if self.cred['ids']:
                    ids_obj = iemlAVIDS.IemlAVIDS(cred=self.cred['ids'],
                                                        debug=self.cred['debug'])
                    ids_obj.start_ids()
            except KeyError:
                self.logger.log(
                    "Intrusion Detection System (IDS) parameter not configured.",
                    logtype="error"
                )

        if self.system_log_provided:
            try:
                sys_obj = engine.SystemLogEngine(debug=self.cred['debug'])
                sys_obj.run()
            except Exception as e:
                self.logger.log(
                    "Error occured: " + str(e),
                    logtype="error"
                )

        if self.server_log_provided:
            server_cred = self.cred['server_log']
            try:
                server_obj = IemlAVServerLog(debug=self.cred['debug'],
                                                log_type=server_cred['log-type'],
                                                log_file=server_cred['log-file'],
                                                window=server_cred['window'],
                                                ip_list=server_cred['ip-list'],
                                                status_code=server_cred['status-code'])
                server_obj.run()
            except KeyError:
                self.logger.log(
                    "Server Log parameters not configured.",
                    logtype="error"
                )
            except Exception as e:
                self.logger.log(
                    "Error occured: " + str(e),
                    logtype="error"
                )

        if self.auto_server_patcher_provided:
            auto_server_patcher_cred = self.cred['auto_server_patcher']
            try:
                patcher_obj = IemlAVAutoServerPatcher(debug=self.cred['debug'],
                                                         cred=auto_server_patcher_cred)
                patcher_obj.start()
            except KeyError:
                self.logger.log(
                    "Auto Server Patcher parameters not configured.",
                    logtype="error"
                )
            except Exception as e:
                self.logger.log(
                    "Error occured: " + str(e),
                    logtype="error"
                )

        

        if self.antivirus_provided:
            antivirus = self.cred['antivirus']
            try:
                antivirus_obj = IemlAVAntiVirus(debug=self.cred['debug'], cred=antivirus)
                antivirus_obj.start()
            except KeyError:
                self.logger.log(
                    "AntiVirus parameters not configured.",
                    logtype="error"
                )
            except Exception as e:
                self.logger.log(
                    "Error occured: " + str(e),
                    logtype="error"
                )

        

    
    

    @staticmethod
    def get_mouse_event():

        with open("/dev/input/mice", "rb") as fh:
            buf = fh.read(3)
            x, y = struct.unpack("bb", buf[1:])
            return x, y

    def get_by_mice(self):

        posx = 0
        posy = 0
        while(1):
            x, y = self.get_mouse_event()
            posx = posx + x
            posy = posy + y
            if (posx > 100 or posy > 100 or posx < -100 or posy < -100):
                posx = 0
                posy = 0
                self.on_move(posx, posy)

    def on_user_update(self):
        """
        Send updates regarding the users currently logged in to the system
        to various platforms.
        """
        msg = self.userLogger.log()
        if msg == "USERS UPDATES\n":
            self.logger.log("NO NEW USERS DETECTED")
            return
        # Shows the warning msg on the console
        self.logger.log(msg, logtype="warning")

        return

    def run_mouse_notifs(self):
        """Run methods for notification using mice activity"""
        time.sleep(10)
        try:
            if not pynput_status:
                self.get_by_mice()
            else:
                while 1:
                    # Starting mouse event listner
                    with mouse.Listener(on_move=self.on_move) as listener:
                        listener.join()
        except Exception as e:
            self.logger.log(
                "Something went wrong: " + str(e) + " End of program",
                logtype="error"
            )
        except KeyboardInterrupt as e:
            self.logger.log(
                "You pressed Ctrl+C!, Bye")
            exit()

    def run_user_notifs(self):
        """Run methods for notification of users added or removed"""
        try:
            from iemlav import users
            self.userLogger = users.IemlAVUserLogger(self.cred['debug'])
            if not pynput_status:
                self.get_by_mice()
            else:
                while 1:
                    # Starting user notifs
                    self.on_user_update()
                    time.sleep(10)
        except Exception as e:
            self.logger.log(
                "Something went wrong: " + str(e) + " End of program",
                logtype="error"
            )
        except KeyboardInterrupt as e:
            self.logger.log(
                "You pressed Ctrl+C!, Bye")
            exit()

    def run(self):

        try:
            t1 = threading.Thread(target=self.run_mouse_notifs)
            t2 = threading.Thread(target=self.run_user_notifs)
            t2.start()
            t1.start()
        except Exception as e:
            self.logger.log(
                "Something went wrong: " + str(e) + " End of program",
                logtype="error"
            )
        except KeyboardInterrupt as e:
            self.logger.log(
                "You pressed Ctrl+C!, Bye")
            exit()
