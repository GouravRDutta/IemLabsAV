# -*- coding: utf-8 -*-

def get_config():
    """Get default configuration credentials."""
    return {

    	"firewall": {
    		"interface": "",
    		"inbound_IPRule": {
    			"action": "0",
    			"ip_inbound": ""
    		},
    		"outbound_IPRule": {
    			"action": "0",
    			"ip_outbound": ""
    		},
    		"protocolRule": {
    			"action": "0",
    			"protocols": "ICMP"
    		},
    		"scanLoad": {
    			"action": "0",
    			"extensions": ".exe"
    		},
    		"source_portRule": {
    			"action": "0",
    			"sports": ""
    		},
    		"dest_portRule": {
    			"action": "0",
    			"dports": ""
    		},
    		"HTTPRequest": {
    			"action": "0"
    		},
    		"HTTPResponse": {
    			"action": "0"
    		},
    		"DNSRule": {
    			"action": "0",
    			"dns": ""
    		},
    		"time": {
    			"time_lb": "00:00",
    			"time_ub": "23:59"
    		}
    	},
    	"ids": {
    		"threshold": 10,
    		"interface": "XXXX"
    	},
    	"server-log": {
    		"log-type": "",
    		"log-file": "",
    		"window": "30",
    		"ip-list": "",
    		"status-code": ""
    	},
    	"auto-server-patcher": {
    		"url": "XXXX",
    		"apache": "1",
    		"sysctl": "1",
    		"login": "1",
    		"ssh": "1"
    	},
    	"antivirus": {
    		"update": "1",
    		"custom-scan": "",
    		"auto-delete": "0",
    		"monitor-usb": "1",
    		"monitor-file-changes": "1",
    		"virustotal-api-key": "XXXX"
    	},
    	"debug": 0
    }
