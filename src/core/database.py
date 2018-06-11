from threading import Lock

class Database(object):
    def __init__(self):
        self.lock = Lock()

    # def __getattribute__(self, value):
    #     with self.lock:
    #         return self.__dict__[value]

    # def __setattr__(self, name, value):
    #     with self.lock:
    #         self.__dict__[name] = value

db = Database()