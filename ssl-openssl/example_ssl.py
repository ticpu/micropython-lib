import ssl
import socket

s = socket.socket()
s.connect(('127.0.0.1', 12123))
z = ssl.wrap_socket(s)
z.write("blabla")
