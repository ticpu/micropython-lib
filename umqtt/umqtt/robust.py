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

    def with_retry(self, meth, *args, **kwargs):
        while 1:
            try:
                return meth(*args, **kwargs)
            except OSError as e:
                print("%r" % e)
            time.sleep(0.5)
            self.reconnect()

    def publish_(self, *args, **kwargs):
        return self.with_retry(super().publish, *args, **kwargs)

    def publish(self, topic, msg, qos=0, retain=False):
        while 1:
            try:
                return super().publish(topic, msg, qos, retain)
            except OSError as e:
                print("%r" % e)
            time.sleep(0.5)
            self.reconnect()

    def wait_msg(self):
        while 1:
            try:
                return super().wait_msg()
            except OSError as e:
                print("%r" % e)
            time.sleep(0.5)
            self.reconnect()
