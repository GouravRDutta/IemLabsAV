
import time
import geocoder
import platform


def get_platform():

    return platform.system() + " " + platform.release()


def getdatetime():
    """Date and time.

    Returns:
        TYPE: String with the current date and time
    """
    return str(time.strftime("%Y-%m-%d %H:%M:%S"))


def check_config(cred):

    for key in cred:
        if cred[key] == "XXXX":
            return False
    return True


def get_current_location():

    geocode_data = geocoder.ip('me')
    dict_data = geocode_data.json

    # Parse the required details
    address = dict_data['address']
    ip = dict_data['ip']

    # Generate message
    msg = "Location: " + address + " (IP: " + ip + " )"
    return msg
