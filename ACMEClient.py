from ACMEConstants import *
from ACMEObjects import Order, Authorization, _Authorization, _Challenge, Certificate
from ACMEUtils import *
from Servers import ChallengeServer
import requests
import json
import dacite
from typing import *
import time
from Crypto.PublicKey import ECC

class ACMEClient:
	def __init__(self, challengeType: int, challengeServer: ChallengeServer,
				 identifiers: List[str], directory: str):
		if DEBUG:
			print('Warning: running application in DEBUG mode')

		self.session = requests.Session()
		self.session.verify = 'pebble.minica.pem'

		self.challengeType = challengeType
		self.challengeServer = challengeServer
		self.identifiers = identifiers
		self.directory = directory
		self.link = dict()
		self._queryDirectory()
		self.nonce = None
		self.getNewNonce()
		self.kid = None
		self.authorizations = None
		self.certificate = None

		self.privKey = ECC.generate(curve='P-256')
		self.pubKey = self.privKey.public_key()


	def _queryDirectory(self):
		r = self.session.get(self.directory, verify=(not DEBUG))
		self.link = json.loads(r.text)

	def postJws(self, link, jws):
		headers = {'Content-Type': 'application/jose+json'}
		r = self.session.post(link, data=jws, headers=headers, verify=(not DEBUG))
		if 'Replay-Nonce' in r.headers:
			self.nonce = r.headers['Replay-Nonce']
		else:
			self.getNewNonce()
		if r.status_code >= 400:
			print(f'Error in POSTing the JWS.\n' + \
				  f'Status code: {r.status_code}' + \
				  f'Headers: {r.headers}' + \
				  f'Body: {r.text}')
		return r

	def postAsGet(self, link):
		payload = ""
		protected = generateProtected(self.nonce, link, kid=self.kid)
		jws = generateJWS(protected, payload, self.privKey)
		r = self.postJws(link, jws)
		return r


	def getNewNonce(self):
		r = self.session.get(self.link['newNonce'], verify=(not DEBUG))
		self.nonce = r.headers['Replay-Nonce']

	def createAccount(self):
		jwk = generateJWK(self.pubKey)

		payload = dict()
		payload['termsOfServiceAgreed'] = True
		payload = json.dumps(payload)

		protected = generateProtected(self.nonce, self.link['newAccount'], jwk=jwk)
		jws = generateJWS(protected, payload, self.privKey)
		r = self.postJws(self.link['newAccount'], jws)
		if r.status_code == 201:
			print('Account created')
			self.kid = r.headers['Location']
		else:
			print('Error while creating a new account')
			print('Status code:', r.status_code)
			print('Response text:', r.text)

	def getAuthorizations(self, authorizationsLinks):
		authorizations = list()
		for link in authorizationsLinks:
			r = self.postAsGet(link)
			if r.status_code == 200:
				response = json.loads(r.text)
				_auth = dacite.from_dict(data_class=_Authorization, data=response)
				auth = Authorization(_auth, link)
				authorizations.append(auth)
				print(f'Got authorization object for {auth.identifier}')
			elif r.status_code >= 400:
				print(f'Error: Could not get authorization object at {link}')
				print(f'Status code: {r.status_code}')
				print('Response headers:\n', r.headers)
				print('Response text:\n', r.text)
		return authorizations

	def placeOrder(self):
		# places order for all elements in self.identifiers
		# for wildcards, nothing changes
		# set self.authorizations, one per each domain type
		self.order = Order(self.identifiers)
		payload = self.order.generateNewOrderJSON()

		protected = generateProtected(self.nonce, self.link['newOrder'], kid=self.kid)
		jws = generateJWS(protected, payload, self.privKey)
		r = self.postJws(self.link['newOrder'], jws)
		if r.status_code == 201:
			print('Order placed')
			self.order.setLocation(r.headers['Location'])
			response = json.loads(r.text)
			self.order.setStatus(response['status'])
			authorizations = self.getAuthorizations(response['authorizations'])
			self.order.setAuthorizations(authorizations)
			self.order.setFinalize(response['finalize'])
		else:
			print('Error while placing a new order')
			print('Status code:', r.status_code)
			print('Response text:', r.text)

	def doChallenge(self, challenge):
		print('Token is:', challenge.token)
		keyAuth = getKeyAuthorization(challenge.token, self.pubKey)
		self.challengeServer.setup(challenge.token, keyAuth)

		# Check the keyAuth is provisioned:
		provisioned = False
		while not provisioned:
			provisioned = self.challengeServer.checkProvisioned()
			if not provisioned:
				time.sleep(1)

	def respondToChallenge(self, challenge):
		payload = '{}'
		protected = generateProtected(self.nonce, challenge.url, kid=self.kid)
		jws = generateJWS(protected, payload, self.privKey)
		r = self.postJws(challenge.url, jws)

		if r.status_code == 200:
			response = r.text
			challenge_status = json.loads(response)['status']
			if challenge_status != 'valid':
				print(f'{challenge.type} challenge could not be completed')
				print(f'Token: {challenge.token}\nStatus: {challenge_status}')
				if 'Retry-After' in r.headers:
					waitingTime = int(r.headers['Retry-After'])
				elif challenge_status != 'invalid':
					waitingTime = VALIDATION_WAITING_TIME
				else:
					waitingTime = -1
				return (False, waitingTime)
			else:
				return (True, None)
		else:
			print('Error in responding to challenge')
			print('Status code:', r.status_code)
			print('Body:', r.text)
			raise ACMEException()

	def ensureAuthorizationValid(self, auth):
		for i in range(MAX_AUTH_VALIDATION_TRIALS):
			r = self.postAsGet(auth.link)
			if r.status_code != 200:
				print('Could not POST-as-GET authorization object')
				return False
			authObject = json.loads(r.text)
			if authObject['status'] == 'valid':
				return True
			elif authObject['status'] == 'invalid':
				return False
			elif authObject['status'] == 'pending':
				if 'Retry-After' in r.headers:
					waitingTime = int(r.headers['Retry-After'])
				else:
					waitingTime = VALIDATION_WAITING_TIME
				if i < MAX_AUTH_VALIDATION_TRIALS-1:
					print(f'Attempt no.{i+1} to check authorization\'s validity has failed.' + \
						  f'Waiting {waitingTime} seconds.')
					time.sleep(waitingTime)
					print(f'Attempt no.{i+2}')
		print(f'Attempt no.{MAX_AUTH_VALIDATION_TRIALS} to check authorization\'s validity has failed.')
		print('Assuming authorization cannot be validated')
		return False


	def obtainAuth(self, auth: Authorization):
		#Retrieves correct challenge type from auth.challenges,
		#accomplishes the challenge by passing it to the correct server.
		#Only when server says the resource has been provisioned,
		#respond to the challenge by POSTing to the challenge link.
		#If it is still 'pending', and if Retry-After is specified, wait for
		#Retry-After seconds. If header not specified, wait for VALIDATION_WAITING_TIME
		#Only when the server says the resource is accessed,
		#Check if auth's status is now 'valid'.
		# If it is still 'pending', and if Retry-After is specified, wait for
		# Retry-After seconds. If header not specified, wait for VALIDATION_WAITING_TIME
		challenge = auth.getChallengeByType(self.challengeType)
		self.doChallenge(challenge)
		completed, _ = self.respondToChallenge(challenge)
		accessed = False
		while not accessed:
			accessed = self.challengeServer.checkAccessed()
			if not accessed:
				time.sleep(1)

		return self.ensureAuthorizationValid(auth)

	def obtainAllAuths(self):
		#Obtains all auths for all elements in self.authorizations
		pendingAuths = self.order.getPendingAuthorizations()
		obtainedAllAuths = True
		for auth in pendingAuths:
			obtained = self.obtainAuth(auth)
			if not obtained:
				print(f'Authorization for {auth.identifier} has not been obtained.')
				print('Not trying next ones')
				obtainedAllAuths = False
				break

		if not obtainedAllAuths:
			print('Error: could not obtain all authorizations needed.')
			raise ACMEException()
		return

	def getOrderStatus(self):
		r = self.postAsGet(self.order.location)
		if r.status_code == 200:
			order_status = json.loads(r.text)['status']
		else:
			print('Error: could not retrieve order object')
			print('Status code:', r.status_code)
			print('Response:', r)
			order_status = None
		return order_status

	def finalizeOrder(self):
		#Check if order's status is 'ready'
		#If so, post CSR to finalize url
		try:
			order_status = self.getOrderStatus()
			if order_status != 'ready':
				print(f'Order is not ready, but with status {order_status}')
				raise ACMEException()

			self.certificate = Certificate()
			csr = createCSR(self.certificate.privKey, self.order.identifiers)
			payload = dict()
			payload['csr'] = csr
			payload = json.dumps(payload)
			protected = generateProtected(self.nonce, self.order.finalize, kid=self.kid)
			jws = generateJWS(protected, payload, self.privKey)
			r = self.postJws(self.order.finalize, jws)

			if r.status_code == 200:
				response = r.text
				order_status = json.loads(response)['status']
				numRetries = 0
				while order_status == 'processing':
					numRetries += 1
					if numRetries > MAX_ORDER_VALIDATION_TRIALS:
						print('Server is taking too long to validate the order.')
						raise ACMEException()
					if 'Retry-After' in r.headers:
						waitingTime = int(r.headers['Retry-After'])
					else:
						waitingTime = ORDER_PROCESSING_WAITING_TIME
					print('Order is processing. Waiting for retry.')
					time.sleep(waitingTime)
					order_status = self.getOrderStatus()
				if order_status != 'valid':
					print('Error: server does not want to issue certificate')
					print('Order status:', order_status)
					print('Order object received:', response)
					raise ACMEException()
			else:
				print('Error: could not POST correctly to finalize link')
				print('Status code:', r.status_code)
			print('CSR POSTed correctly')
		except ACMEException as e:
			raise e

	def downloadCertificate(self):
		#Contact order.certificateURL and
		#set self.certificate to the obtained PEM chain
		r = self.postAsGet(self.order.location)
		if r.status_code == 200:
			response = r.text
			orderObject = json.loads(response)
			certificateLink = orderObject['certificate']
		else:
			print('Error: could not get order object with certificate link')
			raise ACMEException()
		r = self.postAsGet(certificateLink)
		if r.status_code == 200:
			response = r.text
			self.certificate.pem = response
		else:
			print('Error: could not download certificate from provided link')
			raise ACMEException()

	def getPemChain(self):
		return self.certificate.pem

	def getPrivKey(self):
		return convertPrivKeyToPem(self.certificate.privKey)

	def revokeCertificate(self):
		der = convertPemToDer(self.certificate.pem)
		payload = dict()
		payload['certificate'] = der
		payload = json.dumps(payload)
		protected = generateProtected(self.nonce, self.link['revokeCert'], kid=self.kid)
		jws = generateJWS(protected, payload, self.privKey)
		r = self.postJws(self.link['revokeCert'], jws)

		if r.status_code == 200:
			print('Certificate revoked successfully')
		else:
			print('Error: could not revoke certficate')
			print('Response:', r)

