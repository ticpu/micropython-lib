import usocket as socket
import ustruct as struct
from ubinascii import hexlify
import time

class MQTTException(Exception):
    pass

class MQTTClient:

    def __init__(self, client_id, server, port=1883):
        self.client_id = client_id
        self.sock = None
        self.addr = socket.getaddrinfo(server, port)[0][-1]
        self.pid = 0
        self.cb = None

    def set_callback(self, f):
        self.cb = f

    def send_str(self, s):
        self.sock.write(struct.pack("!H", len(s)))
        self.sock.write(s)

    def recv_len(self):
        n = 0
        sh = 0
        while 1:
            b = self.sock.read(1)[0]
            n |= (b & 0x7f) << sh
            if not b & 0x80:
                return n
            sh += 7

    def connect(self, clean_session=True):
        self.sock = socket.socket()
        self.sock.connect(self.addr)
        msg = bytearray(b"\x10\0\0\x04MQTT\x04\x02\0\0")
        msg[1] = 10 + 2 + len(self.client_id)
        msg[9] = clean_session << 1
        self.sock.write(msg)
        print(hex(len(msg)), hexlify(msg, ":"))
        self.send_str(self.client_id)
        resp = self.sock.read(4)
        assert resp[0] == 0x20 and resp[1] == 0x02
        if resp[3] != 0:
            raise MQTTException(resp[3])
        return resp[2] & 1

    def disconnect(self):
        self.sock.write(b"\xe0\0")
        self.sock.close()

    def ping(self):
        self.sock.write(b"\xc0\0")
        self.sock.close()

    def publish(self, topic, msg, qos=0, retain=False):
        assert qos == 0
        pkt = bytearray(b"\x30\0\0")
        pkt[0] |= qos << 1 | retain
        sz = 2 + len(topic) + len(msg)
        assert sz <= 16383
        pkt[1] = (sz & 0x7f) | 0x80
        pkt[2] = sz >> 7
        print(hex(len(pkt)), hexlify(pkt, ":"))
        self.sock.write(pkt)
        self.send_str(topic)
        self.sock.write(msg)

    def subscribe(self, topic, qos=0):
        pkt = bytearray(b"\x82\0\0\0")
        self.pid += 1
        struct.pack_into("!BH", pkt, 1, 2 + 2 + len(topic) + 1, self.pid)
        print(hex(len(pkt)), hexlify(pkt, ":"))
        self.sock.write(pkt)
        self.send_str(topic)
        self.sock.write(qos.to_bytes(1))
        resp = self.sock.read(5)
        print(resp)
        assert resp[0] == 0x90
        assert resp[2] == pkt[2] and resp[3] == pkt[3]
        if resp[4] == 0x80:
            raise MQTTException(resp[4])

    # Returns either (topic, msg) for subscribed messages,
    # or None if internal MQTT message was received (this
    # includes PINGRESP).
    def wait_msg(self):
        res = self.sock.read(1)
        if res is None:
            return None
        self.sock.setblocking(True)
        if res == b"":
            raise OSError(-1)
        if res == b"\xd0":  # PINGRESP
            sz = self.sock.read(1)[0]
            assert sz == 0
            return None
        assert res == b"\x30"
        sz = self.recv_len()
        topic_len = self.sock.read(2)
        topic_len = (topic_len[0] << 8) | topic_len[1]
        topic = self.sock.read(topic_len)
        msg = self.sock.read(sz - topic_len - 2)
        if self.cb is not None:
            self.cb(topic, msg)
        else:
            return (topic, msg)

    # Checks whether a pending message from server is available.
    # If not, returns immediately with None. If a message is
    # available, returns either (topic, msg) for subscribed
    # messages, or None if internal MQTT message was received
    # (this includes PINGRESP).
    def check_msg(self):
        self.sock.setblocking(False)
        return self.wait_msg()
