
import argparse


def get_args():
    
    parser = argparse.ArgumentParser(description='Arguments of IemlAV')

    parser.add_argument(
        '--conf',
        type=str,
        required=False,
        help='Path of config file. default:- "~/.iemlav/iemlav.conf" '
    )

    parser.add_argument(
        '--debug',
        default=False,
        action="store_true",
        help='Degug true or false'
    )

    
    parser.add_argument(
        '--firewall',
        '-f',
        required=False,
        action='store_true',
        help='Start firewall'
    )
    
    parser.add_argument(
        '--interface',
        type=str,
        required=False,
        help='Name of the interface'
    )


    parser.add_argument(
        '--inbound_IP_action',
        type=str,
        required=False,
        help='Inbound IP rule action'
    )

    parser.add_argument(
        '--inbound_IP_list',
        type=str,
        required=False,
        help='List of inbound IPs to look for'
    )

    parser.add_argument(
        '--outbound_IP_action',
        type=str,
        required=False,
        help='Outbound IP rule action (0: BLOCK, 1: ALLOW)'
    )

    parser.add_argument(
        '--outbound_IP_list',
        type=str,
        required=False,
        help='List of outbound IPs to look for'
    )

    parser.add_argument(
        '--protocol_action',
        type=str,
        required=False,
        help='Protocol action (0: BLOCK, 1: ALLOW)'
    )

    parser.add_argument(
        '--protocol_list',
        type=str,
        required=False,
        help='List of protocols to look for'
    )

    parser.add_argument(
        '--scan_action',
        type=str,
        required=False,
        help='Scan load action (0: BLOCK, 1: ALLOW)'
    )

    parser.add_argument(
        '--scan_list',
        type=str,
        required=False,
        help='List of extensions to scan for'
    )

    parser.add_argument(
        '--dest_port_action',
        type=str,
        required=False,
        help='Destination port action (0: BLOCK, 1: ALLOW)'
    )

    parser.add_argument(
        '--dest_port_list',
        type=str,
        required=False,
        help='List of destination ports to look for'
    )

    parser.add_argument(
        '--source_port_action',
        type=str,
        required=False,
        help='Source port action (0: BLOCK, 1: ALLOW)'
    )

    parser.add_argument(
        '--source_port_list',
        type=str,
        required=False,
        help='List of source ports to look for'
    )

    parser.add_argument(
        '--HTTP_request_action',
        type=str,
        required=False,
        help='HTTP request action (0: BLOCK, 1: ALLOW)'
    )

    parser.add_argument(
        '--HTTP_response_action',
        type=str,
        required=False,
        help='HTTP response action (0: BLOCK, 1: ALLOW)'
    )

    parser.add_argument(
        '--dns_action',
        type=str,
        required=False,
        help='DNS action (0: BLOCK, 1: ALLOW)'
    )

    parser.add_argument(
        '--dns_list',
        type=str,
        required=False,
        help='List of DNS to look for'
    )

    parser.add_argument(
        '--time_lb',
        type=str,
        required=False,
        help='Time lower bound'
    )

    parser.add_argument(
        '--time_ub',
        type=str,
        required=False,
        help='Time upper bound'
    )


    parser.add_argument(
        '--url',
        '-u',
        type=str,
        required=False,
        help="URL on which operations are to be performed"
    )

    parser.add_argument(
        '--ids',
        action="store_true",
        required=False,
        help="Start Intrusion Detection System (IDS)"
    )

    parser.add_argument(
        '--threshold',
        '-th',
        type=int,
        required=False,
        help="Intrusion Detection System (IDS) threshold"
    )

    parser.add_argument(
        '--system_log',
        '-sys_log',
        action="store_true",
        required=False,
        help="Start system log monitoring process"
    )

    parser.add_argument(
        '--server-log',
        action="store_true",
        required=False,
        help="Start server log monitoring process"
    )

    parser.add_argument(
        '--log-file',
        type=str,
        required=False,
        help="Path of the log file"
    )

    parser.add_argument(
        '--log-type',
        type=str,
        required=False,
        help="Type of the log file (Apache/Nginx)"
    )

    parser.add_argument(
        '--window',
        type=str,
        required=False,
        help="Days old log to process"
    )

    parser.add_argument(
        '--ip-list',
        type=str,
        required=False,
        help="List of IPs to grab from log file"
    )

    parser.add_argument(
        '--status-code',
        type=str,
        required=False,
        help="List of status code to grab from log file"
    )

    parser.add_argument(
        '--auto-server-patcher',
        '-asp',
        action="store_true",
        required=False,
        help="Start auto server patcher"
    )

    parser.add_argument(
        '--ssh',
        action="store_true",
        required=False,
        help="Patch SSH config"
    )

    parser.add_argument(
        '--sysctl',
        action="store_true",
        required=False,
        help="Patch system configuration"
    )

    parser.add_argument(
        '--login',
        action="store_true",
        required=False,
        help="Patch login configuration"
    )

    parser.add_argument(
        '--apache',
        action="store_true",
        required=False,
        help="Patch apache configuration"
    )

    parser.add_argument(
        '--ssl',
        action="store_true",
        required=False,
        help="Scan for SSL vulnerability"
    )

    parser.add_argument(
        '--path',
        type=str,
        required=False,
        help="Path of the directory"
    )

    parser.add_argument(
        '--server-name',
        type=str,
        required=False,
        help="Name of the server (apache/nginx/etc.)"
    )

    parser.add_argument(
        '--antivirus',
        required=False,
        action="store_true",
        help="Start AntiVirus"
    )

    parser.add_argument(
        '--update',
        required=False,
        type=int,
        help="Auto-update AntiVirus or not (1: yes, 0: no)"
    )

    parser.add_argument(
        '--custom-scan',
        type=str,
        required=False,
        help="Path to custom scan"
    )

    parser.add_argument(
        '--auto-delete',
        required=False,
        type=int,
        help="Auto delete malicious files or manually (1: auto, 0: manual)"
    )

    parser.add_argument(
        '--monitor-usb',
        required=False,
        type=int,
        help="Monitor USB devices or not (1: yes, 0: no)"
    )

    parser.add_argument(
        '--monitor-file-changes',
        required=False,
        type=int,
        help="Monitor file changes or not (1:yes, 0:no)"
    )

    parser.add_argument(
        '--virustotal-api-key',
        required=False,
        action="store_true",
        help="Virus Total API key"
    )

    args = parser.parse_args()
    return args
