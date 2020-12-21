
import platform
import os
import distro

def check_root():

    user = os.getuid()
    if user == 0:
        return True
    else:
        return False


def categorize_os():

    os_name = get_system_name()
    if os_name in ["ubuntu", "kali", "backtrack", "debian"]:
        return "debian"
    # elif some other OS, add their  name
    else:  # if OS not in list
        return None


def get_system_name():

    os_name = distro.linux_distribution()[0]
    print(os_name)
    return os_name.lower()
