from base64 import b64encode, b64decode
import re
import json
from ACMEConstants import *
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.IO import PEM
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicNumbers, EllipticCurvePrivateNumbers

def base64urlEncode(s: bytes):
	output = b64encode(s)
	output = output.split(b'=')[0]
	output = output.replace(b'+', b'-')
	output = output.replace(b'/', b'_')
	return output

def base64urlDecode(s: str):
	output =  s.replace('-', '+')
	output = output.replace('_', '/')

	while len(output)%4 != 0:
		output += '='

	if output[-3:] == '===':
		raise ValueError(f'Input string is malformed according to base64 padding\n' + \
						 f'Input string: {s}')
	return output.encode('utf-8')

def checkBase64Url(s: str):
	pattern = re.compile('[a-zA-Z0-9_-]*')
	if pattern.fullmatch(s) is None:
		return False
	return True

def generateProtected(nonce, url, jwk=None, kid=None):
	protected = dict()
	protected['alg'] = 'ES256'
	if jwk is not None:
		protected['jwk'] = jwk
	elif kid is not None:
		protected['kid'] = kid
	else:
		raise ValueError('JWS Protected Header must have either jwk or kid')
	protected['nonce'] = nonce
	protected['url'] = url
	return json.dumps(protected)

def getSigningInput(protected: bytes, payload: bytes):
	return (protected + b'.' + payload)

def sign(key, msg: bytes):
	h = SHA256.new(msg)
	signature = DSS.new(key, 'fips-186-3').sign(h)
	return signature

def generateJWS(protected: str, payload: str, privKey):
	'''
	Takes as inputs the Protected Header and Payload as JSONs
	Returns a JWS to be POSTed to the ACME server
	'''
	#print('JWS protected:\n', protected)
	#print('JWS payload:\n',   payload)
	protected = base64urlEncode(protected.encode('utf-8'))
	payload = base64urlEncode(payload.encode())
	signingInput = getSigningInput(protected, payload)
	signature = sign(privKey, signingInput) #Using ES256, i.e. ECDSA using P-256 and SHA-256
	signature = base64urlEncode(signature)

	data = dict()
	data['protected'] = protected.decode('utf-8')
	data['payload'] = payload.decode('utf-8')
	data['signature'] = signature.decode('utf-8')
	#print('JWS as dict:\n', data)
	return json.dumps(data)

def generateJWK(pubKey):
	jwk = dict()
	jwk['crv'] = 'P-256'
	jwk['kty'] = 'EC'
	x_int = int(pubKey.pointQ.x)
	y_int = int(pubKey.pointQ.y)
	x_bytes = x_int.to_bytes(COORD_LEN, 'big')
	y_bytes = y_int.to_bytes(COORD_LEN, 'big')
	jwk['x'] = base64urlEncode(x_bytes).decode('utf-8')
	jwk['y'] = base64urlEncode(y_bytes).decode('utf-8')
	return jwk

def getKeyAuthorization(token, pubKey):
	# Shouldn't be problems with stripping leading 0-bytes in the JWK fields
	jwkToHash = json.dumps(generateJWK(pubKey)).replace(' ', '')
	h = SHA256.new(jwkToHash.encode())
	thumbprint = base64urlEncode(h.digest())
	keyAuth = token + '.' + thumbprint.decode('utf-8')
	return keyAuth

def getDnsRecordValue(keyAuth):
	h = SHA256.new(keyAuth.encode())
	return base64urlEncode(h.digest()).decode('utf-8')


def createCSR(privKey, identifiers):
	#base64url of DER format
	#identifiers = [x509.DNSName(identifier) for identifier in identifiers]

	pubNumbers = EllipticCurvePublicNumbers(int(privKey.pointQ.x), int(privKey.pointQ.y), SECP256R1())
	privNumbers = EllipticCurvePrivateNumbers(int(privKey.d), pubNumbers)
	priv_key = privNumbers.private_key()

	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
	    x509.NameAttribute(NameOID.COMMON_NAME, identifiers[0]),
		])).add_extension(
		x509.SubjectAlternativeName([x509.DNSName(identifier) for identifier in identifiers]),
    	critical=False,
		).sign(priv_key, hashes.SHA256())

	der = csr.public_bytes(Encoding.DER)
	return base64urlEncode(der).decode('utf-8')

def convertPrivKeyToPem(privKey):
	return privKey.export_key(format='PEM')

def convertPemToDer(pem):
	cert = x509.load_pem_x509_certificate(pem.encode())
	der = cert.public_bytes(Encoding.DER)
	return base64urlEncode(der).decode('utf-8')



class ACMEException(Exception):
	pass