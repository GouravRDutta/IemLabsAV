# -*- coding: utf-8 -*-


__all__ = ["ProtocolMap",
           "PortMap"]

ProtocolMap = {
    "HOPOPT": "0",
    "ICMP": "1",
    "IGMP": "2",
    "GGP": "3",
    "IP-in-IP": "4",
    "ST": "5",
    "TCP": "6",
    "CBT": "7",
    "EGP": "8",
    "IGP": "9",
    "BBN-RCC-MON": "10",
    "NVP-II": "11",
    "PUP": "12",
    "ARGUS": "13",
    "EMCON": "14",
    "XNET": "15",
    "CHAOS": "16",
    "UDP": "17",
    "MUX": "18",
    "DCN-MEAS": "19",
    "HMP": "20",
    "PRM": "21",
    "XNS-IDP": "22",
    "TRUNK-1": "23",
    "TRUNK-2": "24",
    "LEAF-1": "25",
    "LEAF-2": "26",
    "RDP": "27",
    "IRTP": "28",
    "ISO-TP4": "29",
    "NETBLT": "30",
    "MFE-NSP": "31",
    "MERIT-INP": "32",
    "DCCP": "33",
    "3PC": "34",
    "IDPR": "35",
    "XTP": "36",
    "DDP": "37",
    "IDPR-CMTP": "38",
    "TP++": "39",
    "IL": "40",
    "IPv6": "41",
    "SDRP": "42",
    "IPv6-Route": "43",
    "IPv6-Frag": "44",
    "IDRP": "45",
    "RSVP": "46",
    "GREs": "47",
    "DSR": "48",
    "BNA": "49",
    "ESP": "50",
    "AH": "51",
    "I-NLSP": "52",
    "SWIPE": "53",
    "NARP": "54",
    "MOBILE": "55",
    "TLSP": "56",
    "SKIP": "57",
    "IPv6-ICMP": "58",
    "IPv6-NoNxt": "59",
    "IPv6-Opts": "60",
    "CFTP": "62",
    "SAT-EXPAK": "64",
    "KRYPTOLAN": "65",
    "RVD": "66",
    "IPPC": "67",
    "SAT-MON": "69",
    "VISA": "70",
    "IPCU": "71",
    "CPNX": "72",
    "CPHB": "73",
    "WSN": "74",
    "PVP": "75",
    "BR-SAT-MON": "76",
    "SUN-ND": "77",
    "WB-MON": "78",
    "WB-EXPAK": "79",
    "ISO-IP": "80",
    "VMTP": "81",
    "SECURE-VMTP": "82",
    "VINES": "83",
    "TTP": "84",
    "IPTM": "84",
    "NSFNET-IGP": "85",
    "DGP": "86",
    "TCF": "87",
    "EIGRP": "88",
    "OSPF": "89",
    "Sprite-RPC": "90",
    "LARP": "91",
    "MTP": "92",
    "AX.25": "93",
    "OS": "94",
    "MICP": "95",
    "SCC-SP": "96",
    "ETHERIP": "97",
    "ENCAP": "98",
    "GMTP": "100",
    "IFMP": "101",
    "PNNI": "102",
    "PIM": "103",
    "ARIS": "104",
    "SCPS": "105",
    "QNX": "106",
    "A/N": "107",
    "IPComp": "108",
    "SNP": "109",
    "Compaq-Peer": "110",
    "IPX-in-IP": "111",
    "VRRP": "112",
    "PGM": "113",
    "L2TP": "115",
    "DDX": "116",
    "IATP": "117",
    "STP": "118",
    "SRP": "119",
    "UTI": "120",
    "SMP": "121",
    "SM": "122",
    "PTP": "123",
    "IS-IS over IPv4": "124",
    "FIRE": "125",
    "CRTP": "126",
    "CRUDP": "127",
    "SSCOPMCE": "128",
    "IPLT": "129",
    "SPS": "130",
    "PIPE": "131",
    "SCTP": "132",
    "FC": "133",
    "RSVP-E2E-IGNORE": "134",
    "Mobility Header": "135",
    "UDPLite": "136",
    "MPLS-in-IP": "137",
    "manet": "138",
    "HIP": "139",
    "Shim6": "140",
    "WESP": "141",
    "ROHC": "142",
    "Unassigned": "143-252",
    "Reserved": "255",
}

PortMap = {
      "7": "Echo",
      "554": "RTSP",
      "19": "Chargen",
      "2745": "Bagle.H",
      "2967": "Symantec AV",
      "6970": "Quicktime",
      "560": "rmonitor",
      "3050": "Interbase DB",
      "7212": "GhostSurf",
      "22": "SSH/SCP",
      "563": "NNTP over SSL",
      "3074": "XBOX Live",
      "23": "Telnet",
      "587": "SMTP",
      "3124": "HTTP Proxy",
      "8000": "Internet Radio",
      "25": "SMTP",
      "591": "FileMaker",
      "3127": "MyDoom",
      "8080": "HTTP Proxy",
      "42": "WINS Replication",
      "593": "Microsoft DCOM",
      "3128": "HTTP Proxy",
      "43": "WHOIS",
      "631": "Internet Printing",
      "3222": "GLBP",
      "8118": "Privoxy",
      "49": "TACACS",
      "636": "LDAP over SSL",
      "3260": "iSCSI Target",
      "8200": "VMware Server",
      "53": "DNS",
      "639": "MSDP",
      "3306": "MySQL",
      "8500": "Adobe ColdFusion",
      "646": "LDP",
      "3389": "Terminal Server",
      "8767": "TeamSpeak",
      "69": "TFTP",
      "691": "MS Exchange",
      "3689": "iTunes",
      "70": "Gopher",
      "860": "iSCSI",
      "3690": "Subversion",
      "79": "Finger",
      "873": "rsync",
      "3724": "World of Warcraft",
      "80": "HTTP",
      "902": "VMware Server",
      "21": "FTP",
      "67": "DHCP/BOOTP",
      "88": "Kerberos",
      "110": "POP3",
      "113": "Ident",
      "9800": "WebDAV",
      "4444": "Blaster",
      "9898": "Dabber",
      "995": "POP3 over SSL",
      "4664": "Google Desktop",
      "9988": "Rbot Spybot",
      "4672": "eMule",
      "9999": "Urchin",
      "1026": "1029  Windows Messenger",
      "4899": "Radmin",
      "1080": "MyDoom",
      "5000": "UPnP",
      "5001": "iperf",
      "1194": "OpenVPN",
      "143": "IMAP4",
      "1214": "Kazaa",
      "5004": "RTP",
      "1241": "Nessus",
      "177": "XDMCP",
      "5060": "SIP",
      "179": "BGP",
      "1337": "WASTE",
      "201": "AppleTalk",
      "9119": "MXit",
      "4333": "mSQL",
      "161": "SNMP",
      "123": "NTP",
      "137": "NetBIOS",
      "8086": "Kaspersky AV",
      "993": "IMAP4 over SSL",
      "1025": "Microsoft RPC",
      "119": "NNTP (Usenet)",
      "1433": "Microsoft SQL",
      "5222": "XMPP/Jabber",
      "10000": "BackupExec",
      "10113": "NetIQ",
      "11371": "OpenPGP",
      "12035": "Second Life",
      "12345": "NetBus",
      "13720": "NetBackup",
      "14567": "Battlefield",
      "15118": "Dipnet",
      "264": "BGMP",
      "1512": "WINS",
      "5432": "PostgreSQL",
      "19226": "AdminSecure",
      "318": "TSP",
      "1589": "Cisco VQP",
      "19638": "Ensim",
      "1701": "L2TP",
      "5554": "Sasser",
      "20000": "Usermin",
      "5631": "pcAnywhere",
      "24800": "Synergy",
      "381": "  HP Openview",
      "389": "LDAP",
      "1723": "MS PPTP",
      "411": "Direct Connect",
      "1725": "Steam",
      "443": "HTTP over SSL",
      "1741": "CiscoWorks",
      "445": "Microsoft DS",
      "1755": "MS Media Server",
      "464": "Kerberos",
      "1812": "RADIUS",
      "5800": "VNC over HTTP",
      "5900": "VNC Server",
      "6000": "X11",
      "6112": "Battle.net",
      "25999": "Xfire",
      "27015": "Half -Life",
      "27374": "Sub7",
      "28960": "Call of Duty",
      "465": "SMTP over SSL",
      "1863": "MSN",
      "6129": "DameWare",
      "497": "Retrospect",
      "1985": "Cisco HSRP",
      "6257": "WinMX",
      "500": "ISAKMP",
      "2000": "Cisco SCCP",
      "512": "rexec",
      "2002": "Cisco ACS",
      "6500": "GameSpy Arcade",
      "513": "rlogin",
      "2049": "NFS",
      "6566": "SANE",
      "6588": "AnalogX",
      "514": "syslog",
      "2082": "cPanel",
      "6346": "Gnutella",
      "515": "LPD",
      "2100": "Oracle",
      "6665": "IRC",
      "520": "RIP",
      "2222": "DirectAdmin",
      "6679": "IRC over SSL",
      "521": "RIPng (IPv6)",
      "2302": "Halo",
      "540": "UUCP",
      "2483": "Oracle DB",
      "31337": "Back Orifice",
      "33434": "traceroute",
      "6699": "Napster",
      "6881": "BitTorrent"
}
