import qrcode
import socket
import ssl
import pickle
import hashlib
import base64
import hmac
import binascii
from hashlib import sha512
import os
from random import randint
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from communication import *
import argparse
import time
from argparse import RawTextHelpFormatter


def parseArguments():
	parser = argparse.ArgumentParser(description='StopAndWait', formatter_class=RawTextHelpFormatter)
	parser.add_argument('-v', '--version', action='version', version='')
	parser.add_argument('--sip', default='127.0.0.1', type=str, help='Define server ip')
	parser.add_argument('--sport', type=int, default=5567, help='Define server port')
	parser.add_argument('--tip', default='127.0.0.1', type=str, help='Define turnstile ip')
	parser.add_argument('--tport', type=int, default=5569, help='Define turnstile port')
	parser.add_argument('--auth', type=int, default=5567, help='Amount of authentications')
	parser.add_argument('--cicle', type=int, default=2, help='Define number of cicles')
	parser.add_argument('--index', type=int, default=10, help='Define authentication index limit')

	return parser.parse_args()

class Client(Communication):

	#Client communication data.
	server_sni_hostname = 'iddigital.com'
	client_cert = 'client.pem'
	client_key = 'client.key'
	sip = ''
	sport = ''
	tip = ''
	tport = ''

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
	my_id = ''
	auth_limit = ''
	cicle_limit = ''
	list_time = list()

	def __init__(self, sip, sport, tip, tport, auth_limit, cicle_limit):
		self.sip = sip
		self.sport = sport
		self.tip = tip
		self.tport = tport
		self.auth_limit = auth_limit
		self.cicle_limit = cicle_limit

	def requestAuthentication(self, conn):
		'''
		Function that request authentication to server.
		'''
		# conn.sendall(b'AuthMe') #Send authentication request message.
		ini = time.time()
		if self.authenticationKey == '':
			self.authenticationKey = hashlib.sha256(self.master_key.encode())
			self.authenticationKey = str(self.authenticationKey)
			self.authenticationKey = str(self.authenticationKey.hexdigest())
			self.otpStatus = int(self.otpStatus) + 1
			# print('OTPSTATUS: {}'.format(self.otpStatus))
			print('KEY: {}'.format(self.authenticationKey))
		else:
			new_value = int(self.otpStatus) + 30000
			print(new_value)

			if new_value > self.auth_limit:
				for i in range(self.otpStatus, new_value):
					new_code = hashlib.sha256(self.authenticationKey.encode())
					new_code = str(new_code.hexdigest())
					self.authenticationKey = new_code
				new_value = new_value - (int(new_value/self.auth_limit))*(self.auth_limit)

				# for i in range(self.otpStatus, new_value):
				# 	new_code = hashlib.sha256(self.authenticationKey.encode())
				# 	new_code = str(new_code.hexdigest())
				# 	self.authenticationKey = new_code
				# new_value = new_value - self.auth_limit
			else:
				for i in range(int(self.otpStatus), int(new_value)):
					new_code = hashlib.sha256(self.authenticationKey.encode())
					new_code = str(new_code.hexdigest())
					self.authenticationKey = new_code
			self.otpStatus = new_value
			print('KEY: {}'.format(self.authenticationKey))
			# print('OTPSTATUS: {}'.format(self.otpStatus))
			
		message = str(self.my_id) + '|' + str(self.otpStatus)
		# print('MESSAGEEE: {}\nAUTH: {}\n'.format(message, self.authenticationKey))			
		h = hmac.new(pickle.dumps(self.authenticationKey), pickle.dumps(message), hashlib.sha256)
		h = str(h.hexdigest())
		fim = time.time()
		self.genQRCode(message)
		file_name = str(self.authenticationKey)
		conn.sendall(bytes(h.encode()))
		conn.sendall(bytes(file_name.encode()))

		self.list_time.append(float(fim-ini))
		value = 0
		for i in self.list_time:
			value = value + i
		print('time: {}'.format(value))
		print('HASH: {}\n'.format(h))			
		response = conn.recv(1024)

		if response == b'Auth':
			print('Authenticated!!!')
			pass
		else:
			print('Not authenticated!')
		# pass

	def genAuthenticationKey(self, last_otp, new_otp, key):
		for i in range(int(last_otp), int(new_otp)):
			key = hashlib.sha256(key.encode())
			key = str(key.hexdigest())
		# print("Authentication Key: " + key)
		return key
	def genQRCode(self, message):
		qr = qrcode.QRCode(
			version = 1,
			error_correction = qrcode.constants.ERROR_CORRECT_H,
			box_size = 10,
			border = 4,
			)
		qr.add_data(message)
		qr.make(fit=True)
		img = qr.make_image(fill='black', back_color='white')
		name = str(self.authenticationKey) + ".png"
		img.save(name)

	def requestRegister(self, conn):
		'''
		Function that request register to server.
		'''
		conn.sendall(b'RegisterRequest') #Send register Request.
		code1 = conn.recv(1024).decode()
		code2 = conn.recv(1024).decode()
		code3 = conn.recv(1024).decode()
		self.kt1 = self.gen_kt1(code1, code2, code3)
		# print('Code: {}'.format(code1))
		# print('Code: {}'.format(code2))
		# print('Code: {}'.format(code3))
		# print('KT1: {}'.format(self.kt1))
		self.sendDeviceData(str(self.kt1), conn) #Send device data to server.
		self.kt2 = self.gen_kt2() #Generate temporary key: kt2.
		# print('KT2: {}'.format(self.kt2))
		self.receiveServerData(conn) #Receive server random number.
		self.printData() #Just print all data.
		self.genmaster_key() #Generate master key.
		self.sendProofkm(conn)
		self.receiveServerProofkm(conn)
		self.authenticationKey = self.master_key
		self.otpStatus = 0
		self.my_id = conn.recv(1024).decode() #Receive 'id' from server.
		print('ID: {}'.format(self.my_id))
		print("Closing connection")
	
	def getOtpStatus(self, otpStatus):
		'''
		Function that return the OTAC STATUS.
		'''
		if otpStatus == '': #Test if it's the first authentication.
			otpStatus = str(1)
			# print("OTAC STATUS: " + otpStatus)
			return otpStatus
		else:
			# print("OTAC STATUS: " + otpStatus)
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
		self.master_key = self.kt1 + self.kt2 + self.app_rand1 + self.server_rand + self.imei
		self.master_key = hashlib.sha256(self.master_key.encode())
		self.master_key = str(self.master_key.hexdigest())
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
		print('Decrypted: {}'.format(decryptedData))
		self.server_rand = decryptedData

	def sendDeviceData(self, kt1, conn):
		'''
		Function that send device data.
		'''
		self.imei = str(randint(100000000,999999999)) #Generate random imei.
		self.app_rand1 = str(randint(100000000,999999999)) #Generate application random number.
		self.deviceData = self.imei + "|" + self.app_rand1 #Concatenate device data.
		print('device data {}  {}'.format(self.imei, self.app_rand1))
		encrypted = self.encrypt(bytes(kt1, "utf-8"), bytes(self.deviceData,"utf-8"), True) #Encrypt data.
		conn.sendall(pickle.dumps(encrypted)) #Send encrypted data to server.
		
	def sendProofkm(self, conn):
		'''
		Function that send data to proof that kt2 match.
		'''
		self.randNumProof = str(randint(10000000, 99999999)) #Generate another random number.
		encryptedRanNum = self.encrypt(bytes(self.master_key, "utf-8"), bytes(self.randNumProof, "utf-8")) #Encrypt random number.
		hashRanNum = hashlib.sha256(encryptedRanNum.encode())
		hashRanNum = str(hashRanNum.hexdigest()) #Generate the number hash.
		conn.sendall(bytes(encryptedRanNum.encode()))
		conn.sendall(bytes(hashRanNum.encode()))
		# conn.sendall(pickle.dumps(encryptedRanNum)) #Send encrypted number.
		# conn.sendall(pickle.dumps(hashRanNum)) #Send number hash.

	def receiveServerProofkm(self,conn):
		'''
		Function that receive data to proof that kt2 match.
		'''
		serverHash = conn.recv(1024).decode() #Receive server hash.
		hashProof = hashlib.sha256(str(int(self.randNumProof) + 1).encode()) #Generate own hash to compare.
		hashProof = str(hashProof.hexdigest())
		try:
			if serverHash == hashProof: #Test if it matchs.
				print("MASTER KEY AUTHENTICATED")
		except:
			print("Error on match hashes...")
			pass

	def listen(self):
		# Cifragem só na associação. Não na autenticação.
		'''
		Function to connect with server.
		'''

		context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.server_cert)
		context.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)

		try:
			for i in range(0,1): #Just to test some authentication requests
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				conn = context.wrap_socket(s, server_side=False, server_hostname=self.server_sni_hostname)
				conn.connect((self.sip, self.sport))
				# print("SSL established. Peer: {}".format(conn.getpeercert()))
				print("Sending: 'Register Request")
				self.requestRegister(conn) #Call Register request functions.
				conn.close()
				# print("Connection Closed!1")
				# print("#####################\n")

		except:
		    print("Unable to register")

		try:
			ini = time.time()
			t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)				
			t.connect((self.tip, self.tport))
			# t2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			# t2.connect(('127.0.0.1', 9090))

			# t2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			# t2.connect(('127.0.0.1', 9090))


			for i in range(0,10000): #Just to test some authentication requests.
				print(i)
				self.requestAuthentication(t) #Call Authentication request function.
				# t.close()
				# time.sleep(0.01)
			t.close()
			time.sleep(1)
			# t2.connect(('127.0.0.1', 9090))
			# for i in range(0,1): #Just to test some authentication requests.

			# 	self.requestAuthentication(t2) #Call Authentication request function.
			# t2.close()
			time.sleep(1)
			# for i in range(0,4): #Just to test some authentication requests.
			# 	print(i)
				
			# 	self.requestAuthentication(t) #Call Authentication request function.
				# t.close()
				# time.sleep(0.01)
			# for i in range(0,1): #Just to test some authentication requests.
			# 	t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)				
			# 	t.connect((self.tip, self.tport))
	
			# 	self.requestAuthentication(t) #Call Authentication request function.
			# 	t.close()
				

			fim = time.time()
			# print('Tempo:{}'.format(fim-ini))
		except:
			print("Unable to authenticate")
			pass

if __name__ == '__main__':
	args = parseArguments()
	client = Client(args.sip, int(args.sport), args.tip, int(args.tport), args.index, args.cicle)
	client.listen()