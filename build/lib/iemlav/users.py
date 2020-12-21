
import time
import sqlite3
import psutil


connection = sqlite3.connect('/etc/iemlav/db.sqlite3')

connection.execute('''CREATE TABLE IF NOT EXISTS USERS(
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    NAME CHAR(100),
    IP CHAR(100),
    dt TIMESTAMP
    );''')


class IemlAVUserLogger():
    

    BOLD = '\033[1m'
    ENDC = '\033[0m'
    BLUE = '\033[94m'
    VIOLET = '\033[95m'
    OKGREEN = '\033[92m' + BOLD + "Info : " + ENDC + '\033[92m'
    WARNING = '\033[93m' + BOLD + "Warn : " + ENDC + '\033[93m'
    ERROR = '\033[91m' + BOLD + "Error: " + ENDC + '\033[91m'
    YELLOW = '\033[33m'

    def __init__(self, debug=False):
        """Init logger params.

        Args:
            debug (bool): Script validity
        """

        self.LEGEND = self.VIOLET + '[' + ']' + \
            '  ' + self.YELLOW + '[ ' + \
            str(time.strftime("%Y-%m-%d %H:%M")) + ' ]  '
        self.debug = debug

    def addUsers(self):

        message = "USERS UPDATES\n"
        cur_users = []
        for user in psutil.users():
            cur_users.append((user.name, user.host))

        users = list(connection.execute("SELECT NAME,IP FROM USERS"))
        for user in users:
            if user not in cur_users:
                connection.execute("DELETE FROM USERS WHERE NAME=\"" + \
                                    user[0] + "\" AND IP=\"" + user[1] + "\"")
                message += ("REMOVED USER:- NAME: " +
                            user[0] + " IP: " + user[1] + "\n")

        for user in cur_users:
            if user not in users:
                connection.execute("INSERT INTO USERS (NAME, IP, dt) \
                    VALUES (?, ?, ?)", (user[0], user[1], time.strftime("%Y-%m-%d %H:%M")))
                connection.commit()
                message += "ADDED USER:- NAME: " + user[0] + " IP: " + user[1] + "\n"
        print(self.LEGEND + self.OKGREEN + message + self.ENDC)
        return message

    def log(self):
        """
        For adding users.

        Args:
            None
        """
        return self.addUsers()
