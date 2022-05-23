DEBUG = False

# Challenge types
HTTP_01 = 'http-01'
DNS_01 = 'dns-01'

#Servers' ports
CHALL_HTTP_PORT = 5002
DNS_PORT  = 10053
HTTPS_WEB_PORT = 5001
SHUTDOWN_PORT = 5003
ACME_SERVER_PORT = 14000

# Default values for retry waiting times
VALIDATION_WAITING_TIME = 5
ORDER_PROCESSING_WAITING_TIME = 5
DNS_RTT = 3

#Max attempts to challenges' response
MAX_AUTH_VALIDATION_TRIALS = 3
MAX_ORDER_VALIDATION_TRIALS = 3

#EC Cryptography constants
COORD_LEN = 32

# Certificate and key files
CERT_FILE = 'cert.pem'
KEY_FILE  = 'key.pem'

