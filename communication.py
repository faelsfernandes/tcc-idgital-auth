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

	def genKeyK(self,code1, code2, code3):
		'''
		Function to generate temporary key: key_k.
		'''
		key_k = str(code1) + str(code2) + str(code3) #Concatenate strings.
		key_k = hashlib.sha256(key_k.encode()).hexdigest() #Get key_k hash.  
		return key_k

	def genKeyM(self):
		'''
		Function to generate temporary key: key_k.
		'''
		key_m = str(self.imei) + str(self.appRandomNumber) + str(self.key_k)
		key_m = hashlib.sha256(key_m.encode()).hexdigest() #Get key_k hash.  
		return key_m

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
		print("key_k: " + str(self.key_k))
		print("key_m: " + str(self.key_m))
		print("appRandomNumber: " + str(self.appRandomNumber))
		print("serverRandomNumber: " + str(self.serverRandomNumber))
		print("imei: " + str(self.imei))

