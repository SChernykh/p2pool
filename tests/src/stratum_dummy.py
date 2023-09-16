# This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
# Copyright (c) 2021-2023 SChernykh <https://github.com/SChernykh>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import socket
import time
import sys
import json

f = open('stratum_dummy' + sys.argv[1] + '.log', 'wb')

f.write(b'Connecting')
f.flush()

while True:
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(1)
	sock.setblocking(True)

	if sock.connect_ex(('127.0.0.1', 3333)) == 0:
		break;

	sock.close()

	f.write(b'.')
	f.flush()
	print('.')
	time.sleep(1)

f.write(b'\n')
f.flush()

diff = ''

if (sys.argv[1] == '2'):
	diff = '+1000'
if (sys.argv[1] == '3'):
	diff = '+10000000'

msg_id = 1

request = '{"id":' + str(msg_id) + ',"method":"login","params":{"login":"x' + diff + '"}}\n'
msg_id += 1
s = '-> ' + request
print(s, end='')
sock.sendall(request.encode('utf-8'))

f.write(s.encode('utf-8'))
f.flush()

rpc_id = ''

while True:
	data = sock.recv(1024)
	if len(data) == 0:
		break

	s = '<- ' + data.decode('utf-8')
	print(s, end='')

	f.write(s.encode('utf-8'))
	f.flush()

	obj = json.loads(data)
	job_id = ''

	if ('method' in obj) and ('params' in obj) and (obj['method'] == 'job'):
		job_id = obj['params']['job_id']
		target = obj['params']['target']
	elif ('result' in obj) and ('job' in obj['result']):
		if ('id' in obj['result']):
			rpc_id = obj['result']['id']
		job_id = obj['result']['job']['job_id']
		target = obj['result']['job']['target']

	if (job_id != ''):
		if (msg_id < 4):
			result = ('f' if (msg_id == 2) else '0') * 64
			request = '{"id":' + str(msg_id) + ',"method":"submit","params":{"id":"' + rpc_id + '","job_id":"' + job_id + '","nonce":"ffffffff","result":"' + result + '"}}\n'
		elif (msg_id == 4):
			request = '{"id":' + str(msg_id) + ',"method":"keepalived"}\n'
		else:
			t = bytearray.fromhex(target)
			for i in range(len(t)):
				if (t[i] > 0):
					t[i] -= 1
					break
				else:
					t[i] = 255

			result = ('f' * (64 - len(target))) + t.hex()
			request = '{"id":' + str(msg_id) + ',"method":"submit","params":{"id":"' + rpc_id + '","job_id":"' + job_id + '","nonce":"ffffffff","result":"' + result + '"}}\n'

		msg_id += 1
		s = '-> ' + request
		print(s, end='')
		sock.sendall(request.encode('utf-8'))

		f.write(s.encode('utf-8'))
		f.flush()

sock.close()
f.close()
