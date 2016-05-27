import time
from umqtt.robust import MQTTClient

c = MQTTClient("umqtt_client", "localhost")
if not c.connect(clean_session=False):
    print("Empty session")
    c.subscribe(b"foo_topic")

while 1:
    print(c.wait_msg())

c.disconnect()
