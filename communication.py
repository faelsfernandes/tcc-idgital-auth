import socket
import ssl
import re
import pickle
import hashlib
import base64
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
from random import randint
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

class Communication():
	addr = '127.0.0.1'
	port = 5567
	server_cert = 'server.pem'
	
	def __ini__(self):
		pass

	def gen_kt1(self,code1, code2, code3):
		'''
		Function to generate temporary key: kt1.
		'''
		# kt1 = str(code1) + str(code2) + str(code3) #Concatenate strings.
		kt1 = code1 + code2 + code3 #Concatenate strings.
		kt1 = hashlib.sha256(kt1.encode()) #Get kt1 hash.  
		kt1 = str(kt1.hexdigest())
		return kt1

	def gen_kt2(self):
		'''
		Function to generate temporary key: kt1.
		'''
		kt2 = self.imei + self.app_rand1 + self.kt1
		kt2 = hashlib.sha256(kt2.encode()).hexdigest() #Get kt1 hash.  
		return kt2

	def encrypt(self,key, source, encode=True):
		'''
		Function that encrypt data.
		'''
		key = SHA256.new(key).digest()  #Use SHA-256 to get a proper-sized AES Key.
		IV = Random.new().read(AES.block_size)  #Generate inicialization vector.
		encryptor = AES.new(key, AES.MODE_CBC, IV) #Generate a AES key like.
		padding = AES.block_size - len(source) % AES.block_size  #Calculate needed padding
		source += bytes([padding]) * padding  #Add padding;
		data = IV + encryptor.encrypt(source)  #Store the IV at the beginning and encrypt;
		# print(data)
		return base64.b64encode(data).decode("utf-8") if encode else data

	def decrypt(self,key, source, decode=True):
		'''
		Function that decrypt data.
		'''
		if decode:
			source = base64.b64decode(source.encode("utf-8"))
		key = SHA256.new(key).digest()  #Use SHA-256 to get a proper-sized AES key.
		IV = source[:AES.block_size]  #Extract inicialization vector.
		decryptor = AES.new(key, AES.MODE_CBC, IV) #Generate AES key like.
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

