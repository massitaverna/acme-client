from ACMEConstants import *
from ACMEUtils import checkBase64Url
from dataclasses import dataclass
from typing import *
from datetime import datetime, timedelta
import json
from Crypto.PublicKey import ECC


@dataclass
class Identifier:
	type: str
	value: str

@dataclass
class _Challenge:
	type: str
	url: str
	status: str
	token: str
	validated: Optional[str]

@dataclass
class _Authorization:
	identifier: Identifier
	status: str
	expires: Optional[str]
	challenges: List[_Challenge]
	wildcard: Optional[bool]

class Challenge:
	def __init__(self):
		self.type = None
		self.url = None
		self.token = None

class Authorization:
	def __init__(self, _auth: _Authorization, link: str):
		self.challenges = list()
		for _challenge in _auth.challenges:
			challenge = Challenge()
			if _challenge.type in [HTTP_01, DNS_01]:
				challenge.type = _challenge.type
			else:
				print(f'Challenge type {_challenge.type} not recognized' + \
					'\nOmitting this challenge from authorization object')
				continue
			challenge.url = _challenge.url
			if not checkBase64Url(_challenge.token):
				raise ValueError(f'Challenge {_challenge} has invalid token {_challenge.token}' + \
								'\nOmitting this challenge from authorization object')
				continue
			challenge.token = _challenge.token
			self.challenges.append(challenge)

		self.identifier = _auth.identifier
		self.status = _auth.status
		self.wildcard = _auth.wildcard
		self.link = link

	def getChallengeByType(self, challengeType: str):
		for challenge in self.challenges:
			if challenge.type == challengeType:
				return challenge
		print(f'Error: no challenge of type {challengeType} can be found ' + \
			  f'for the authorization of {self.identifier}')
		return None

class Order:
	def __init__(self, identifiers: List[str]):
		self.identifiers = identifiers
		self.status = None
		self.location = None
		self.authorizations = None
		self.finalize = None
	
	def generateNewOrderJSON(self):
		identifiers = list()
		for identifier in self.identifiers:
			id_dict = dict()
			id_dict['type'] = 'dns'
			id_dict['value'] = identifier
			identifiers.append(id_dict)

		notBefore = datetime.now().replace(microsecond=0).astimezone()
		oneHour = timedelta(hours=1)
		notAfter = notBefore + oneHour

		order = dict()
		order['identifiers'] = identifiers
		order['notBefore'] = notBefore.isoformat()
		order['notAfter'] = notAfter.isoformat()

		return json.dumps(order)

	def setStatus(self, status):
		self.status = status

	def setLocation(self, location):
		self.location = location

	def setAuthorizations(self, authorizations):
		self.authorizations = authorizations

	def getPendingAuthorizations(self):
		pendingAuths = list()
		for auth in self.authorizations:
			if auth.status == 'pending':
				pendingAuths.append(auth)
		return pendingAuths

	def setFinalize(self, finalize):
		self.finalize = finalize

class Certificate:
	def __init__(self):
		self.privKey = ECC.generate(curve='P-256')
		self.pubKey = self.privKey.public_key()
		self.pem = None
