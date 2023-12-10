import http.server
import socketserver
import json

chain_id = ''
aux_blob = ''
aux_diff = 1000
aux_hash = ''

counter = 0

class Server(http.server.BaseHTTPRequestHandler):
	def do_POST(self):
		length = int(self.headers['content-length'])
		request = self.rfile.read(length)
		print(request.decode('utf-8'))
		request = json.loads(request.decode('utf-8'))

		self.send_response(200)
		self.send_header('Content-type', 'application/json')
		self.end_headers()

		response = {'jsonrpc':'2.0','id':'0'}

		if request['method'] == 'merge_mining_get_chain_id':
			response['result'] = {'chain_id':chain_id}
		elif request['method'] == 'merge_mining_get_job':
			global counter
			counter += 1
			s = aux_blob + '_' + str(counter // 10)
			aux_hash = hashlib.sha256(s.encode('utf-8')).hexdigest()
			if aux_hash != request['params']['aux_hash']:
				response['result'] = {'aux_blob':s.encode('utf-8').hex(),'aux_diff':aux_diff,'aux_hash':aux_hash}
			else:
				response['result'] = {}
		elif request['method'] == 'merge_mining_submit_solution':
			response['result'] = {'status':'accepted'}
        
		response = json.dumps(response);
		print(response)
		self.wfile.write(response.encode('utf-8'))
        
if __name__ == "__main__":
	from sys import argv
	import hashlib

	port = int(argv[1])
	chain_id = hashlib.sha256(argv[2].encode('utf-8')).hexdigest()
	aux_blob = argv[3];

	httpd = socketserver.TCPServer(('', port), Server)
	httpd.serve_forever()
