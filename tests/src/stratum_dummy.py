import socket
import time
import sys

f = open(sys.argv[1], 'wb');

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)
sock.setblocking(True)

time.sleep(5)

while sock.connect_ex(('127.0.0.1', 3333)) != 0:
	f.write(b'.\n')
	print('.')
	time.sleep(1)

sock.sendall(b'{"id":1,"method":"login","params":{"login":"x"}}\n')

while True:
	data = sock.recv(1024)
	if len(data) == 0:
		break;
	f.write(data)
	f.flush()
	print(data.decode('utf-8'))

sock.close()
f.close()
