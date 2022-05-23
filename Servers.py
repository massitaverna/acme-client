from flask import Flask
import socket
import requests
from threading import Thread
import time
from ACMEConstants import *
from ACMEUtils import getDnsRecordValue
from dnslib.server import DNSServer as Nameserver
from dnslib.dns import QTYPE, RR, DNSRecord

class ChallengeServer:
	def __init__(self):
		self.accessed = False

	def getThread(self):
		pass
		
	def setup(self):
		pass

	def checkProvisioned(self) -> bool:
		pass

	def checkAccessed(self):
		return self.accessed

class HTTPServer(ChallengeServer):
	def __init__(self, recordIP):
		self.serverStarted = False
		self.keyAuth = ''
		self.token = ''
		#Check which hostname the testing system looks for
		#(maybe 127.0.0.1, or 0.0.0.0)
		self.serverIP = recordIP
		self.app = Flask(__name__)
		self.thread = Thread(target=lambda: self.app.run(
			host=self.serverIP, port=CHALL_HTTP_PORT, debug=False))
		self.thread.daemon = True
		self.thread.start()
		#self.app.run(host=self.serverIP, port=CHALL_HTTP_PORT, debug=False)

	def getThread(self):
		return self.thread

	def provisionKeyAuth(self):
		self.accessed = True
		return self.keyAuth

	def setup(self, token: str, keyAuth: str):
		if not self.serverStarted:
			self.waitForServerStarted()
		self.serverStarted = True

		self.accessed = False
		self.keyAuth = keyAuth
		self.token = token
		self.app.add_url_rule('/.well-known/acme-challenge/' + token,
			view_func=self.provisionKeyAuth,
			methods=['GET'])

	def waitForServerStarted(self):
		url = 'http://' + self.serverIP + ':' + str(CHALL_HTTP_PORT)
		started = False
		while not started:
			try:
				r = requests.get(url)
				started = True
			except requests.exceptions.ConnectionError as e:
				time.sleep(1)

	def checkProvisioned(self):
		url = 'http://' + self.serverIP + ':' + str(CHALL_HTTP_PORT) + \
			  '/.well-known/acme-challenge/' + self.token
		r = requests.get(url)
		self.accessed = False
		if r.text == self.keyAuth:
			return True
		return False

class DNSResolver:
	def __init__(self, recordIP, domainNames):
		self.recordIP = recordIP
		self.domainNames = domainNames
		self.recordValue = ''
		self.accessed = False

	def setTxtResponse(self, recordValue):
		self.recordValue = recordValue

	def resolve(self, request, handler):
		reply = request.reply()
		if request.q.qtype == getattr(QTYPE, 'A'):
			domainName = str(request.q.get_qname())
			zone = domainName + ' 60 A ' + self.recordIP
			print('Building reply from string ' + zone)
			reply.add_answer(*RR.fromZone(zone))
		elif request.q.qtype == getattr(QTYPE, 'TXT'):
			validationDN = str(request.q.get_qname())
			prefix = '_acme-challenge.'
			if validationDN[:len(prefix)] == prefix:
				DN = validationDN[len(prefix):-1]
				if DN in self.domainNames:
					zone = validationDN + ' 300 TXT \"' + self.recordValue + '\"'
					reply.add_answer(*RR.fromZone(zone))
					self.accessed = True
				else:
					print('Error: domain name asked differs from domain name to be validated')
			else:
				print('Error: cannot recognize validation domain name format')
		else:
			print(f'Query type {request.q.qtype} unknown. Ignoring it')
		return reply

class DNSServer(ChallengeServer):
	def __init__(self, recordIP, domainNames):
		self.domainNames = domainNames
		self.recordValue = ''
		self.resolver = DNSResolver(recordIP, domainNames)
		self.nameserver = Nameserver(self.resolver, port=DNS_PORT, address="0.0.0.0")
		self.nameserver.start_thread()

	def setup(self, token, keyAuth):
		self.resolver.accessed = False
		self.recordValue = getDnsRecordValue(keyAuth)
		self.resolver.setTxtResponse(self.recordValue)

	def waitForServerStarted(self):
		started = False
		while not started:
			q = DNSRecord.question("www.abc.com", qtype='A')
			try:
				q.send("localhost", DNS_PORT, timeout=DNS_RTT) # Will wait for response
				started = True
			except socket.timeout:
				pass

	def checkProvisioned(self):
		DN = '_acme-challenge.' + self.domainNames[0]
		q = DNSRecord.question(DN, qtype='TXT')
		a = None
		try:
			a = q.send("localhost", DNS_PORT, timeout=DNS_RTT) # Will wait for response
			a = DNSRecord.parse(a)
		except socket.timeout:
			return False

		if self.recordValue in a.rr[0].rdata.toZone():
			self.resolver.accessed = False
			return True
		else:
			return False

	def checkAccessed(self):
		return self.resolver.accessed

	def stop(self):
		self.nameserver.stop()



class HTTPSWebServer:
	def __init__(self, recordIP):
		self.serverIP = recordIP
		self.app = Flask(__name__)
		self.thread = Thread(target=lambda: self.app.run(
			host=self.serverIP, port=HTTPS_WEB_PORT, debug=False,
			ssl_context=(CERT_FILE, KEY_FILE)))
		self.thread.daemon = True
		self.thread.start()
		self.app.add_url_rule('/', view_func=self.homePage, methods=['GET'])

	def homePage(self):
		return 'Hello World'


class ShutdownServer():
	def __init__(self, recordIP):
		self.serverIP = recordIP
		self.app = Flask(__name__)
		self.thread = Thread(target=lambda: self.app.run(
			host=self.serverIP, port=SHUTDOWN_PORT, debug=False))
		self.thread.daemon = True
		self.thread.start()
		self.app.add_url_rule('/shutdown', view_func=self.informShutdown, methods=['GET'])
		self.shutdownReceived = False

	def informShutdown(self):
		self.shutdownReceived = True
		return 'Shutdown signal sent to all servers'

	def waitForShutdownSignal(self):
		while not self.shutdownReceived:
			time.sleep(1)