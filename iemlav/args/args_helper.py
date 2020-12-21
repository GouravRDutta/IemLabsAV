
import platform
from iemlav import logger
import sys
import json
from iemlav.args.config import get_config
def iterate_dict(config_dict, default):
    
    skip = False
    for key, item in config_dict.items():
        if not skip:
            if not isinstance(item, dict):
                if int(platform.sys.version_info[0]) < 3:  # if Python 2.X.X
                    val = raw_input('>> Enter {}: '
                                    .format(item)).strip()
                else:
                    val = str(input('>> Enter {}: '.format(item))).strip()
                if (val == 's' or
                    val == 'S'):
                    skip = True
                    return None
                elif val == None:
                    config_dict[key] = default[key]
                else:
                    config_dict[key] = val
            else:
                sub_dict = iterate_dict(config_dict[key],
                                        default[key])
                if sub_dict is not None:
                    config_dict[key] = sub_dict
                else:
                    return None
        else:
            return None
    return config_dict


def read_creds(path):
    """Returns JSON creds as dict."""
    with open(path) as f:
        creds = json.load(f)
        return creds
        
def load_default(key):
    
    path = 'iemlav.conf'
    try:
        creds = read_creds(path)
        return creds[key]
    except FileNotFoundError:
        creds = get_config()
        return creds[key]

def takeInput(func):
    
    def inner_wrapper(*args):
        print('\n[!] Enter (S/s) to skip...')
        dict_value = func(*args)
        config_dict = dict_value['input']
        default = dict_value['default']
        config_dict = iterate_dict(config_dict,
                                   default)
        return config_dict
    return inner_wrapper


class ArgsHelper(object):

    def __init__(self, args):

        """Initialize ArgsHelper"""
        self.modulename = 'args_helper'

        self.cred = {}
        self.args = args

        if self.args.debug:
            self.cred['debug'] = self.args.debug
        else:
            self.cred['debug'] = False
            


        self.cred_provided = False
        self.firewall_provided = False
        self.ids_provided = False
        self.system_log_provided = False
        self.server_log_provided = False
        self.auto_server_patcher_provided = False
        self.antivirus_provided = False
        
        # Setup logger
        self.logger = logger.IemlAVLogger(
            self.modulename,
            self.cred['debug']
        )

    

    @takeInput
    def configureFirewall(self):
        """
        Returns the format to configure Firewall.
        """
        self.logger.log('Firewall configuration setup')
        default = load_default('firewall')
        return {
            'input': {
                "interface": "Firewall-- interface name",
            	"inbound_IPRule": {
            		"action": "inbound IP action (0: BLOCK, 1: ALLOW)",
            		"ip_inbound": "list of inbound IPs to look for"
            	},
            	"outbound_IPRule": {
            		"action": "outbound IP action (0: BLOCK, 1: ALLOW)",
            		"ip_outbound": "list of outbound IPs to look for"
            	},
            	"protocolRule": {
            		"action": "protocol action (0: BLOCK, 1: ALLOW)",
            		"protocols": "list of protocols to look for"
            	},
            	"scanLoad": {
            		"action": "scan download action (0: BLOCK, 1: ALLOW)",
            		"extensions": "list of extensions to scan for"
            	},
            	"source_portRule": {
            		"action": "source port action (0: BLOCK, 1: ALLOW)",
            		"sports": "list of source ports"
            	},
            	"dest_portRule": {
            		"action": "destination port action (0: BLOCK, 1: ALLOW)",
            		"dports": "list of destination ports"
            	},
            	"HTTPRequest": {
            		"action": "HTTP request action (0: BLOCK, 1: ALLOW)"
            	},
            	"HTTPResponse": {
            		"action": "HTTP response action (0: BLOCK, 1: ALLOW)"
            	},
            	"DNSRule": {
            		"action": "DNS action (0: BLOCK, 1: ALLOW)",
            		"dns": "list of dns to look for"
            	},
            	"time": {
            		"time_lb": "time lower bound (eg. 00:00)",
            		"time_ub": "time upper bound (eg. 23:59)"
            	}
            },
            'default': default
        }

    @takeInput
    def configureIDS(self):
        """
        Returns the format to configure IDS.
        """
        self.logger.log("IDS configuraton setup")
        default = load_default("ids")
        return {
            "input": {
                "threshold": " IDS-- threshold settings (integer value: 10 - 1000)",
                "interface": "interface on which to monitor"
                },
                "default": default
        }

    @takeInput
    def configureServerLogMonitor(self):
        """
        Returns the format to configure Server Log Monitor.
        """
        self.logger.log("Server Log Monitor setup")
        default = load_default("server-log")
        return {
            "input": {
                "log-type": " Serverlog-- type of log file (Apache/Nginx)",
                "log-file": "path of log file (else leave blank)",
                "window": "days old log file to process (default: 30)",
                "ip-list": "list of IPs to grab, sep. by comma",
                "status-code": "list of status code to look for, sep. by comma"
            },
            "default": default
        }

    @takeInput
    def configureAutoServerPatcher(self):
        """
        Returns the format to configure Auto Server Patcher.
        """
        self.logger.log("Auto Server Patcher setup")
        default = load_default("auto-server-patcher")
        return {
            "input":{
                "url": "Auto Server Patcher-- url to scan for SSL vulnerability, else leave blank",
                "apache": "whether to patch Apache config (0/1)?",
                "sysctl": "whether to patch sysctl (0/1)?",
                "ssh": "whether to patch SSH config (0/1)?",
                "login": "whether to patch login config (0/1)?"
            },
            "default": default
        }


    @takeInput
    def configureAntiVirus(self):
        """
        Returns the format to configure AntiVirus.
        """
        self.logger.log("AntiVirus configuration setup")
        default = load_default("antivirus")
        return {
            "input": {
                "update": "AntiVirus-- whether to update (1) or not (0)",
                "custom-scan": "whether to perform a full scan (leave blank) or custom scan (enter path)",
                "auto-delete": "whether to auto-delete (1) malicious files or manually (0)",
                "monitor-usb": "whether to monitor USB device (1) or not (0)",
                "monitor-file-changes": "whether to monitor file changes (1) or not (0)",
                "virustotal-api-key": "VirusTotal API key"
            },
            "default": default
        }

    def check_args(self):
        
        if ((len(sys.argv) == 1) or
           (len(sys.argv) == 2 and self.args.debug)):  # Peform all integration

            

            # Start the firewall configuration setup
            firewall = self.configureFirewall()
            if firewall:
                self.cred['firewall'] = firewall
                self.firewall_provided = True


            # Start the IDS configuration setup
            ids = self.configureIDS()
            if ids:
                self.cred["ids"] = ids
                self.ids_provided = True

            # Start the server log setup
            server_log = self.configureServerLogMonitor()
            if server_log:
                self.cred["server_log"] = server_log
                self.server_log_provided = True

            # Start the Auto Server Patcher setup
            auto_server_patcher = self.configureAutoServerPatcher()
            if auto_server_patcher:
                self.cred['auto_server_patcher'] = auto_server_patcher
                self.auto_server_patcher_provided = True


            # Start the AntiVirus setup
            antivirus = self.configureAntiVirus()
            if antivirus:
                self.cred['antivirus'] = antivirus
                self.antivirus_provided = True


  

        if self.args.firewall and not self.firewall_provided:
            firewall = self.configureFirewall()
            if firewall:
                self.cred['firewall'] = firewall
                self.firewall_provided = True

        if self.args.ids and not self.ids_provided:
            ids = self.configureIDS()
            if ids:
                self.cred["ids"] = ids
                self.ids_provided = True

        if self.args.system_log and not self.system_log_provided:
            self.system_log_provided = True

        if self.args.server_log and not self.server_log_provided:
            server_log = self.configureServerLogMonitor()
            if server_log:
                self.cred["server_log"] = server_log
                self.server_log_provided = True

        if self.args.antivirus:
            antivirus = self.configureAntiVirus()
            if antivirus:
                self.cred["antivirus"] = antivirus
                self.antivirus_provided = True

        if (self.args.auto_server_patcher and
            not self.auto_server_patcher_provided and
            not self.args.url and not self.args.apache and
            not self.args.ssh and not self.args.login and
            not self.args.sysctl):
            auto_server_patcher = self.configureAutoServerPatcher()
            if auto_server_patcher:
                self.cred['auto_server_patcher'] = auto_server_patcher
                self.auto_server_patcher_provided = True
                
                

        if not self.ids_provided:
            if (self.args.threshold and self.args.interface):
                ids = {}
                ids["threshold"] = self.args.threshold
                ids["interface"] = self.args.interface
                self.cred["ids"] = ids
                self.ids_provided = True

        if not self.server_log_provided:
            if (self.args.server_log and
                self.args.log_file and
                self.args.log_type and
                self.args.window and
                self.args.ip_list and
                self.args.status_code):
                server_log = {}
                server_log["log-file"] = self.args.log_file
                server_log["log-type"] = self.args.log_type
                server_log["window"] = self.args.window
                server_log["ip-list"] = self.args.ip_list
                server_log["status-code"] = self.args.status_code
                self.cred["server-log"] = server_log
                self.server_log_provided = True

        if not self.auto_server_patcher_provided:
            if (self.args.auto_server_patcher and
               (self.args.url or
                self.args.apache or
                self.args.sysctl or
                self.args.login or
                self.args.ssh)):
                auto_server_patcher = {}
                auto_server_patcher['url'] = self.args.url
                auto_server_patcher['apache'] = self.args.apache
                auto_server_patcher['sysctl'] = self.args.sysctl
                auto_server_patcher['login'] = self.args.login
                auto_server_patcher['ssh'] = self.args.ssh
                self.cred['auto_server_patcher'] = auto_server_patcher
                self.auto_server_patcher_provided = True

        if not self.antivirus_provided:
            if (self.args.update and
                self.args.auto_delete and
                self.args.monitor_usb and
                self.args.monitor_file_changes and
                self.args.virustotal_api_key):
                antivirus = {}
                antivirus['update'] = self.args.update
                antivirus['custom-scan'] = self.args.custom_scan
                antivirus['auto-delete'] = self.args.auto_delete
                antivirus['monitor-usb'] = self.args.monitor_usb
                antivirus['monitor-file-changes'] = self.args.monitor_file_changes
                antivirus['virustotal-api-key'] = self.args.virustotal_api_key

        if not self.firewall_provided:
            if (self.args.interface or
                isinstance(self.args.inbound_IP_action, int) or
                isinstance(self.args.inbound_IP_list, str) or
                isinstance(self.args.outbound_IP_action, int) or
                isinstance(self.args.outbound_IP_list, str) or
                isinstance(self.args.protocol_action, int) or
                isinstance(self.args.protocol_list, str) or
                isinstance(self.args.scan_action, int) or
                isinstance(self.args.scan_list, str) or
                isinstance(self.args.dest_port_action, int) or
                isinstance(self.args.dest_port_list, str) or
                isinstance(self.args.source_port_action, int) or
                isinstance(self.args.source_port_list, str) or
                isinstance(self.args.dns_action, int) or
                isinstance(self.args.dns_list, str) or
                isinstance(self.args.HTTP_request_action, int) or
                isinstance(self.args.HTTP_response_action, int) or
                isinstance(self.args.time_lb, str) or
                isinstance(self.args.time_ub, str)):

                # Initialize empty firewall configuraton dictionary
                firewall = {}

                # Create configuration dictionary
                firewall['interface'] = self.args.interface
                firewall['inbound_IPRule'] = {
                                    'action': self.args.inbound_IP_action,
                                    'ip_inbound': self.args.inbound_IP_list
                                }
                firewall['outbound_IPRule'] = {
                                    'action': self.args.outbound_IP_action,
                                    'ip_outbound': self.args.outbound_IP_list
                                }
                firewall['protocolRule'] = {
                                    'action': self.args.protocol_action,
                                    'protocols': self.args.protocol_list
                                }
                firewall['scanLoad'] = {
                                    'action': self.args.scan_action,
                                    'extensions': self.args.scan_list
                                }
                firewall['source_portRule'] = {
                                    'action': self.args.source_port_action,
                                    'sports': self.args.source_port_list
                                }
                firewall['dest_portRule'] = {
                                    'action': self.args.dest_port_action,
                                    'dports': self.args.dest_port_list
                                }
                firewall['HTTPRequest'] = {
                                    'action': self.args.HTTP_request_action
                                }
                firewall['HTTPResponse'] = {
                                    'action': self.args.HTTP_response_action
                                }
                firewall['DNSRule'] = {
                                'action': self.args.dns_action,
                                'dns': self.args.dns_list
                            }
                firewall['time'] = {
                            'time_lb': self.args.time_lb,
                            'time_ub': self.args.time_ub
                        }

                self.cred['firewall'] = firewall
                self.firewall_provided = True

        if (
            self.firewall_provided or
            self.ids_provided or
            self.system_log_provided or
            self.server_log_provided or
            self.auto_server_patcher_provided or
            self.antivirus_provided):
            self.cred_provided = True

        return {
            'cred': self.cred,
            'cred_provided': self.cred_provided,
            'firewall_provided': self.firewall_provided,
            'ids_provided': self.ids_provided,
            'system_log_provided': self.system_log_provided,
            'server_log_provided': self.server_log_provided,
            'auto_server_patcher_provided': self.auto_server_patcher_provided,
            'antivirus_provided': self.antivirus_provided,
        }
