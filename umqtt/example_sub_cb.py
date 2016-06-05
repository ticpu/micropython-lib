import time
from umqtt.simple import MQTTClient

def sub_cb(topic, msg):
    print((topic, msg))

c = MQTTClient("umqtt_client", "localhost")
c.set_callback(sub_cb)
c.connect()
c.subscribe(b"foo_topic")

while 1:
    c.wait_msg()
    #c.check_msg()
    #time.sleep(1)

c.disconnect()
