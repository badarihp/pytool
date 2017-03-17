#!/usr/bin/env python
# Reflects the requests from HTTP methods GET, POST, PUT, and DELETE
# Written by Nathan Hamiel (2010)

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser
import datetime
import sys
import socket
import json
import urllib
import urllib2, re, base64
from urlparse import urlparse

username="as1@cisco1.com"
password="as_password"

mtdata='''
{
	"address": "tel:+1234567890",
	"ref_id": 1,
	"data": "que sera, sera!",
	"callback": {
		"uri": "http://berv:9000",
		"token": "123456789050"
	}
}
'''

class RequestHandler(BaseHTTPRequestHandler):

    def processODR(self, request_headers, data):
        cType = request_headers.getheaders('Content-Type')[0]
        print(cType)
        if("json" not in cType):
            print("Error App != json")
            return;
       ##callBackUrl=data['MODataAction']['callback']['uri']
       #callBackUrl="http://localhost:8182/api/tdata"
       #print("------------------->", callBackUrl)
       #post_req = urllib2.Request(callBackUrl)
       ##resp=json.loads(mtdata)
       ##callBackUrl=data['MODataAction']['callback']['uri']
       #resp=json.loads(mtdata)
       #base64string = base64.encodestring('%s:%s' % (username, password))[:-1]
       #authheader =  "Basic %s" % base64string

       ##post_req.add_data(urllib.urlencode({'json': json.dumps(resp)}))
       ##post_req.add_data(urllib.urlencode({'' : json.dumps(resp)}))
       #post_req.add_header("Authorization", authheader)
       #post_req.add_header("Content-Type", "application/json")
       #post_req.add_header("Cache-Control", "no-cache")

       #jsondata = json.dumps(resp)
       #jsondataasbytes = jsondata.encode('utf-8')   # needs to be bytes
       #post_req.add_header('Content-Length', len(jsondataasbytes))
       #print (jsondataasbytes)
       #

       #response = urllib2.urlopen(post_req, jsondataasbytes)
       #response.close()
        

    
    def do_GET(self):
        
        request_path = self.path
        
        print("\n----- Request Start ----->\n")
        print(request_path)
        print(self.headers)
        print("<----- Request End -----\n")
        
        self.send_response(200)
        self.send_header("Set-Cookie", "foo=bar")
        
    def do_POST(self):
        
        request_path = self.path
        
        print("\n----- Request Start ----->\n")
        print(request_path)
        request_headers = self.headers
        content_length = request_headers.getheaders('content-length')
        length = int(content_length[0]) if content_length else 0
        print(request_headers)
        data_string = self.rfile.read(length)
        print(data_string)
        print("\n----- Request End ----->\n")
        if(request_path == "/api/odata"):
            print("Process MO data POST REQ")
            self.send_response(200)
            #Send back resp and initiate call back uri
            #data = json.loads(data_string)
            #self.processODR(request_headers, data)
        else:
	    print("\n---Received MT data ---\n")
            self.send_response(200)
    
    do_PUT = do_POST
    do_DELETE = do_GET
        
def main():
    port = 9000
    HOST=([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
    print('Listening on ' + HOST + ':'+str(port))
    server = HTTPServer((HOST, port), RequestHandler)
    server.serve_forever()

        
if __name__ == "__main__":
    parser = OptionParser()
    parser.usage = ("Creates an http-server that will echo out any GET or POST parameters\n"
                    "Run:\n\n"
                    "   reflect")
    (options, args) = parser.parse_args()
    
    main()
