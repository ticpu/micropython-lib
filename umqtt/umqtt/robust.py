import time
from . import simple

class MQTTClient(simple.MQTTClient):

    def reconnect(self):
        while 1:
            try:
                return super().connect(False)
            except OSError as e:
                print("reconnect: %r" % e)
                time.sleep(1)

    def wait_msg(self):
        while 1:
            try:
                return super().wait_msg()
            except OSError as e:
                print("%r" % e)
            time.sleep(0.5)
            self.reconnect()
