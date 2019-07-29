import argparse
from argparse import RawTextHelpFormatter
import socket
import ssl
import pickle
import hashlib
import base64
from random import randint
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from communication import *

class Client(Communication):

	#Client communication data.
	server_sni_hostname = 'iddigital.com'
	client_cert = 'client.pem'
	client_key = 'client.key'

	#Data.
	kt1 = ''
	kt2 = ''
	imei = ''
	app_rand1 = ''
	server_rand = ''
	deviceData = ''
	randNumProof = ''
	otpStatus = ''
	authenticationKey = ''
	master_key = ''

	def __init__(self):
		pass

	def requestAuthentication(self, conn):
		'''
		Function that request authentication to server.
		'''
		conn.send(b'AuthenticationRequest') #Send authentication request message.
		self.otpStatus = self.getOtpStatus(self.otpStatus) #Get OTP Status.
		conn.send(pickle.dumps(self.otpStatus)) #Send OTP satatus.
		if self.authenticationKey == '': #Test if it's the first authentication.
			self.authenticationKey = self.genAuthenticationKey(self.otpStatus, self.master_key)
		else:
			self.authenticationKey = self.genAuthenticationKey(self.otpStatus, self.authenticationKey)

		conn.send(pickle.dumps(self.authenticationKey)) #Send authentication code.
		receivedResponse = str(conn.recv(1024), "utf-8") #Receive the server response.

		if receivedResponse == "AuthenticationSucessful": #Threat the server response.
			print("Authentication Sucessful!")
			self.otpStatus = str(int(self.otpStatus) + 1)
		else:
			print("Failed authentication")

	def requestRegister(self, conn, name):
		'''
		Function that request register to server.
		'''
		conn.send(b'RegisterRequest') #Send register Request.
		conn.send(pickle.dumps(name))
		code1 = pickle.loads(conn.recv(1024)) #Receive 'tls' code from server.
		code2 = pickle.loads(conn.recv(1024)) #Receive 'sms' code from server.
		code3 = pickle.loads(conn.recv(1024)) #Receive 'e-mail' code from server.
		self.kt1 = self.gen_kt1(code1,code2,code3) #Generate temporary key: kt1.
		self.sendDeviceData(str(self.kt1), conn) #Send device data to server.
		self.kt2 = self.gen_kt2() #Generate temporary key: kt2.
		self.receiveServerData(conn) #Receive server random number.
		self.printData() #Just print all data.
		self.genmaster_key() #Generate master key.
		self.sendProofkm(conn)
		self.receiveServerProofkm(conn)
		print("Closing connection")

	def genAuthenticationKey(self, otpStatus, key):
		'''
		Function that generate authentication key.
		'''
		for i in range(0,int(otpStatus)): #Just do the hash according to otpStatus value.
			key = hashlib.sha256(key.encode()).hexdigest()
		print("Authentication Key: " + key)
		return key
	
	def getOtpStatus(self, otpStatus):
		'''
		Function that return the OTP status.
		'''
		if otpStatus == '': #Test if it's the first authentication.
			otpStatus = str(randint(1, 50000))
			print("OTP STATUS: " + otpStatus)
			return otpStatus
		else:
			print("OTP STATUS: " + otpStatus)
			return otpStatus

	def gen_kt1(self,code1, code2, code3):
		'''
		Function to generate temporary key: kt1.
		'''
		kt1 = str(code1) + str(code2) + str(code3) #Concatenate strings.
		kt1 = hashlib.sha256(kt1.encode()).hexdigest() #Get kt1 hash.  
		return kt1

	def gen_kt2(self):
		'''
		Function to generate temporary key: kt1.
		'''
		kt2 = str(self.imei) + str(self.app_rand1) + str(self.kt1)
		kt2 = hashlib.sha256(kt2.encode()).hexdigest() #Get kt1 hash.  
		return kt2

	def genmaster_key(self):
		'''
		Function that generate master key.
		'''
		self.master_key = str(self.kt1) + str(self.kt2) + str(self.app_rand1) + str(self.server_rand) + str(self.imei)
		self.master_key = hashlib.sha256(self.master_key.encode()).hexdigest()
		print("MASTER KEY: " + self.master_key)

	def encrypt(self,key, source, encode=True):
		'''
		Function that encrypt data.
		'''
		key = SHA256.new(key).digest()  #Yse SHA-256 to get a proper-sized AES Key.
		IV = Random.new().read(AES.block_size)  #Generate inicialization vector.
		encryptor = AES.new(key, AES.MODE_CBC, IV)
		padding = AES.block_size - len(source) % AES.block_size  #Calculate needed padding
		source += bytes([padding]) * padding  #Add padding;
		data = IV + encryptor.encrypt(source)  #Store the IV at the beginning and encrypt;
		return base64.b64encode(data).decode("utf-8") if encode else data

	def decrypt(self,key, source, decode=True):
		'''
		Function that decrypt data.
		'''
		if decode:
		    source = base64.b64decode(source.encode("utf-8"))
		key = SHA256.new(key).digest()  #Use SHA-256 to get a proper-sized AES key.
		IV = source[:AES.block_size]  #Extract inicialization vector.
		decryptor = AES.new(key, AES.MODE_CBC, IV)
		data = decryptor.decrypt(source[AES.block_size:])  #Decrypt data.
		padding = data[-1]  #Get the padding value.
		if data[-padding:] != bytes([padding]) * padding: #Test padding.
		    raise ValueError("Invalid padding...")
		return data[:-padding]  #Remove padding.

	def printData(self):
		'''
		Function that just print all data.
		'''
		print("kt1: " + str(self.kt1))
		print("kt2: " + str(self.kt2))
		print("app_rand1: " + str(self.app_rand1))
		print("server_rand: " + str(self.server_rand))
		print("imei: " + str(self.imei))


	def receiveServerData(self, conn):
		'''
		Function that receive server data.
		'''
		serverData = pickle.loads(conn.recv(1024)) #Receive device data.
		decrypted = self.decrypt(bytes(self.kt2, "utf-8"), serverData, True)
		decryptedData = str(decrypted, "utf-8")
		self.server_rand = decryptedData

	def sendDeviceData(self, kt1, conn):
		'''
		Function that send device data.
		'''
		self.imei = randint(100000000,999999999) #Generate random imei.
		self.app_rand1 = randint(100000000,999999999) #Generate application random number.
		self.deviceData = str(self.imei) + "|" +str(self.app_rand1) #Concatenate device data.
		encrypted = self.encrypt(bytes(kt1, "utf-8"), bytes(self.deviceData,"utf-8"), True) #Encrypt data.
		conn.send(pickle.dumps(encrypted)) #Send encrypted data to server.
		
	def sendProofkm(self, conn):
		'''
		Function that send data to proof that kt2 match.
		'''
		self.randNumProof = str(randint(10000000, 99999999)) #Generate another random number.
		encryptedRanNum = self.encrypt(bytes(self.master_key, "utf-8"), bytes(self.randNumProof, "utf-8")) #Encrypt random number.
		hashRanNum = hashlib.sha256(encryptedRanNum.encode()).hexdigest() #Generate the number hash.
		conn.send(pickle.dumps(encryptedRanNum)) #Send encrypted number.
		conn.send(pickle.dumps(hashRanNum)) #Send number hash.

	def receiveServerProofkm(self,conn):
		'''
		Function that receive data to proof that kt2 match.
		'''
		serverHash = pickle.loads(conn.recv(1024)) #Receive server hash.
		hashProof = hashlib.sha256(str(int(self.randNumProof) + 1).encode()).hexdigest() #Generate own hash to compare.
		try:
			if serverHash == hashProof: #Test if it matchs.
				print("MASTER KEY AUTHENTICATED")
		except:
			print("Error on match hashes...")

	def connect(self, action, id):
		'''
		Function to connect with server.
		'''
		server_sni_hostname = 'iddigital.com'
		server_cert = 'server.pem'
		client_cert = 'client.pem'
		client_key = 'client.key'

		context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.server_cert)
		context.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)

		if action == "Register":
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				conn = context.wrap_socket(s, server_side=False, server_hostname=self.server_sni_hostname)
				conn.connect((self.addr, self.port))
				print("SSL established. Peer: {}".format(conn.getpeercert()))
				print("Sending: 'Register Request")
				self.requestRegister(conn) #Call Register request functions.
				conn.close()
				print("Connection Closed!1")

			except:
			    print("Unable to connect1")
		else:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				conn = context.wrap_socket(s, server_side=False, server_hostname=self.server_sni_hostname)
				conn.connect((self.addr, self.port))
				print("SSL established. Peer: {}".format(conn.getpeercert()))
				print("Sending: 'Authentication request")
				
				self.requestAuthentication(conn, i)doracl #Call Authentication request function.
				conn.close()
				print("Connection Closed!2")
			except:
				print("Unable to connect2")

def parseArguments():
	'''
	Função que identifica os argumentos passados.

	:returns: parser -- objetos contendo os argumentos.
	'''

	parser = argparse.ArgumentParser(description='SAMU - Catraca', formatter_class=RawTextHelpFormatter)
	parser.add_argument("-v", "--version", action='version', version='Catraca v1.0')
	parser.add_argument("--register", action="store_const",const=True, help="Solicita registro")
	parser.add_argument("--name", action="store_const", help="Define nome do usuario")
	parser.add_argument("--auth", action="store_const", const=True, help="Solicita autenticacao")
	parser.add_argument("--id", help="Define id do usuario")

	return parser.parse_args()

if __name__ == '__main__':
	args = parseArguments()
	if args.register == True:
		if args.name == '':
			print("Falta o nome")
		else:
			client = Client()
			client.connect("Register")
	elif args.auth == True::
		if args.id == '':
			print("Falta o ID")
		else:
			client. = Client()
			client.connect("Auth")
	else:
		print("Problema ao processar requisicao")


	# client = Client()
	# client.connect()