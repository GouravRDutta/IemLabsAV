

import json
import platform
import hashlib
import threading
import subprocess
import os


# Create thread lock
lock = threading.Lock()


def json_to_dict(path):

    try:
        with open(path, "r") as json_data_file:
            data = json.load(json_data_file)
            return data
    except Exception as e:
        print(e)


def categorize_os():

    os_name = get_system_name()
    if os_name in ["ubuntu", "kali", "backtrack", "debian"]:
        return "debian"
    # elif some other OS, add their  name
    else:  # if OS not in list
        return None


def get_system_name():

    os_name = platform.dist()[0]
    return os_name.lower()


def extractBytes(file_path):

    with open(file_path, "rb") as rf:
        return rf.read()


def get_md5_hash(file_path):

    extracted_bytes = extractBytes(file_path)
    hash_value = hashlib.md5(extracted_bytes).hexdigest()
    return hash_value


def open_file(path):

    with open(path) as f:
        return f.readlines()


def write_data(path, data):

    lock.acquire()
    with open(path, "a+") as f:
        f.write(data + "\n")
        lock.release()
    lock.release()


def excecute_command(command):

    command = command.split(' ')
    process_respose = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
    output, error = process_respose.communicate()

    if output:
        output = output.decode('utf-8')
    if error:
        error = error.decode('utf-8')

    return output, error


def check_root():

    user = os.getuid()
    if user == 0:
        return True
    else:
        return False
