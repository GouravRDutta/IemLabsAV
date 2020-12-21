#!/bin/python
# -*- coding: utf-8 -*-
"""Docstring."""
import os
import platform
import time
from iemlav.core import IemlAV


if __name__ == '__main__':

    secT = IemlAV()
    try:
        time.sleep(5)
        platform = platform.system()
        if platform == 'Linux':
            command = 'sudo pm-suspend'
            os_name = platform.dist()[0]
            os_major_version = platform.dist()[1].split('.')[0]
            if os_name == 'Ubuntu' and int(os_major_version) >= 16:
                command = 'systemctl suspend'
            os.system(command)
        if platform == 'Darwin':
            os.system('pmset sleepnow')
        if platform == 'Windows':
            os.system('rundll32.exe powerprof.dll, SetSuspendState 0,1,0')
    except Exception as e:
        print(e)
    secT.run()
