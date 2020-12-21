# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup
import distro
import subprocess
import re
import platform

os_name = distro.linux_distribution()[0]

if not os_name:
    if 'amzn' in platform.uname()[2]:
        os_name = 'centos'

files_definition = [
    ('/etc/iemlav', ['iemlav.conf']),
    ('', ['iemlav.conf']),
    ('/etc/iemlav/asp', [
        'iemlav/lib/auto_server_patcher/configs/commands.json',
        'iemlav/lib/auto_server_patcher/configs/config.json'
    ]),
    ('/etc/iemlav/log_monitor/server_log/payloads', [
        'iemlav/lib/log_monitor/server_log/rules/payloads/bad_ua.txt',
        'iemlav/lib/log_monitor/server_log/rules/payloads/lfi.txt',
        'iemlav/lib/log_monitor/server_log/rules/payloads/port_scan_ua.txt',
        'iemlav/lib/log_monitor/server_log/rules/payloads/sqli.txt',
        'iemlav/lib/log_monitor/server_log/rules/payloads/web_shell.txt',
        'iemlav/lib/log_monitor/server_log/rules/payloads/xss.txt']),
    ('/etc/iemlav/log_monitor/server_log/regex', [
        'iemlav/lib/log_monitor/server_log/rules/regex/sqli.txt',
        'iemlav/lib/log_monitor/server_log/rules/regex/xss.txt']),
    ('/etc/iemlav/log_monitor/system_log', [
        'iemlav/lib/log_monitor/system_log/harmful_command.txt'
    ]),
    ('/etc/iemlav/antivirus', [
        'iemlav/lib/antivirus/config/config.json'
    ])
]

# dependency-name to command mapping dict
DEPENDENCY_COMMAND_MAP = {
    "libnetfilter-queue-dev": {"debian": "sudo apt-get install "
                                         "build-essential python-dev "
                                         "libnetfilter-queue-dev"},
    "clamav": {"debian": "sudo apt-get install clamav"}
}



def execute_command(command):

    success = True

    try:
        output = subprocess.check_output(command, shell=True)
    except subprocess.CalledProcessError:
        success = False

    if success:
        return output.decode("utf-8")
    else:
        return None


def verify_installation(output):

    found = re.findall(
        r'([0-9]+\supgraded).*([0-9]+\snewly installed)',
        output
    )

    upgraded = found[0][0]
    installed = found[0][1]

    upgraded_num = re.findall(r'^[0-9]+', upgraded)
    upgraded_num = int(upgraded_num[0])

    installed_num = re.findall(r'^[0-9]+', installed)
    installed_num = int(installed_num[0])

    if (upgraded_num > 0 or installed_num > 0):
        return True


def install_dependency(dependency, command):
    
    print("[!] installing ", dependency)
    # install the dependency
    output = execute_command(command)
    if output:
        if verify_installation(output):
            print("[+] ", dependency, " --installed")
        else:
            print("[-] ", dependency, "--failed")


def check_dependency():
    """Check for the dependencies in the system."""
    # categorize OS
    if os_name.lower() in ["ubuntu", "kali", "debian"]:
        system = "debian"
    # elif some other based OS
    else:  # if OS not in listing
        print("[!] No suitable command for OS: {0}".format(os_name))
        # exit & continue with rest of the installation
        return

    for dependency in DEPENDENCY_COMMAND_MAP.keys():

        flag = 0

        # if debian
        if system == "debian":
            # command for debian based OS to check installed or not
            command = "dpkg -s " + dependency + " |grep Status"
            output = execute_command(command)

            if output:
                if "install ok installed" in output:
                    print("[!] ", dependency, " --already installed")
                    flag = 1  # installed

        # elif some other based OS
        # add logic here to check whether dependency is installed

        # not installed (common for all)
        if flag == 0:
            # get the OS specific command
            command = DEPENDENCY_COMMAND_MAP[dependency][system]
            install_dependency(dependency, command)

check_dependency()


entry_points = {
    'console_scripts': [
        'iemlav=iemlav.entry_points.iemlav_core_ep:run_core',
        'iemlav-server=iemlav.entry_points.server_ep:start_server_process',
        'iemlav-system=iemlav.entry_points.system_ep:start_system_process',
        'iemlav-iot=iemlav.entry_points.iot_ep:start_iot_process'
    ]
}

server_requirements = [
    "pathlib",
    "wget",
    "yara-python",
    "clamd",
    "beautifulsoup4",
    "lxml",
    "clamd"
]

system_requirements = [
    "pathlib",
    "wget",
    "yara-python",
    "clamd",
    "beautifulsoup4",
    "lxml",
    "clamd"
]

setup(
    name='iemlav',
    version='0.1',
    packages=find_packages(exclude=["test",
                                    "*.test",
                                    "*.test.*",
                                    "test.*"]),
    data_files=files_definition,
    entry_points=entry_points,
    scripts=['iemlav.py'],
    license='MIT',
    description='IemlAV',
    url='https://github.com/iemaofficial/IEMLabs-Product',
    author='IEMLabs(Development Team)',
    author_email='gouravdutta11@gmail.com',
    install_requires=[
        "requests",
        "requests_oauthlib",
        "py_cpuinfo",
        "psutil",
        "flask",
        "flask_cors",
        "pynput",
        "python-telegram-bot",
        "twilio",
        "boto3",
        "geocoder",
        "pyudev",
        "ipwhois",
        "future",
        "scapy",
        "wget",
        "bs4",
        "shodan",
        "NetfilterQueue"
    ],
    extras_require={
        'server': server_requirements,
        'system': system_requirements,
    },
    python_requires='>=2.7',
    classifiers=[
        'Development Status :: 1 - Beta',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Natural Language :: English',
        'Topic :: Software Development :: Version Control :: Git',
        'Topic :: Software Development :: Testing :: Unit',
    ],
    zip_safe=False
)
