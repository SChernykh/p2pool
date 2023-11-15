import http.server
import socketserver
import json

class Server(http.server.BaseHTTPRequestHandler):
	def do_POST(self):
		length = int(self.headers['content-length'])
		request = self.rfile.read(length)
		print(request.decode('utf-8'))
		request = json.loads(request)

		self.send_response(200)
		self.send_header('Content-type', 'application/json')
		self.end_headers()

		response = {'jsonrpc':'2.0','id':'0'}

		if request['method'] == 'merge_mining_get_chain_id':
			response['result'] = {'chain_id':'0f28c4960d96647e77e7ab6d13b85bd16c7ca56f45df802cdc763a5e5c0c7863'}
		elif request['method'] == 'merge_mining_get_job':
			response['result'] = {'aux_blob':'4c6f72656d20697073756d','aux_diff':123456,'aux_hash':'f6952d6eef555ddd87aca66e56b91530222d6e318414816f3ba7cf5bf694bf0f'}
		elif request['method'] == 'merge_mining_submit_solution':
			response['result'] = {'status':'accepted'}
        
		response = json.dumps(response);
		print(response)
		self.wfile.write(response.encode('utf-8'))
        
httpd = socketserver.TCPServer(('', 8000), Server)
httpd.serve_forever()
