from PIL import Image
from pyzbar.pyzbar import decode
import pyqrcode
import qrtools
import socket
import ssl
import re
import pickle
import time
import hmac
import os
import hashlib
import base64
from communication import *
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
from random import randint
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import argparse
from argparse import RawTextHelpFormatter


def parseArguments():
	parser = argparse.ArgumentParser(description='StopAndWait', formatter_class=RawTextHelpFormatter)
	parser.add_argument('-v', '--version', action='version', version='')
	parser.add_argument('--sip', default='127.0.0.1', type=str, help='Define server ip')
	parser.add_argument('--sport', type=int, default=5567, help='Define server port')
	parser.add_argument('--tip', default='127.0.0.1', type=str, help='Define turnstile ip')
	parser.add_argument('--tport', type=int, default=5569, help='Define turnstile port')
	return parser.parse_args()

class Turnstile:

	sip = ''
	tip = ''
	sport = 5567
	tport = 5568
	server_sni_hostname = 'iddigital.com'
	server_cert = 'server.pem'
	turnstile_cert = 'client.pem'
	turnstile_key = 'client.key'
	user_list = {}
	# client_cert = 'client.pem'
	# client_key = 'client.key'

	user_list = {}

	def __init__(self, sip, sport, tip, tport):
		self.sip = sip
		self.sport = sport
		self.tip = tip
		self.tport = tport	

	def genAuthenticationKey(self, cli_otp, server_otp, code):
		# for i in range(int(server_otp),(int(cli_otp) - int(server_otp))):
		for i in range(int(server_otp),(int(cli_otp) - int(server_otp))):
			code = hashlib.sha256(code.encode())
			code = str(code.hexdigest())
		# print("Authentication Key: " + code)
		return code

	def requestAuth(self, sconn, cconn):
		message = pickle.loads(cconn.recv(1024))
		cli_hash = pickle.loads(cconn.recv(1024))	
		# message = cconn.recv(1024)
		# cli_hash = cconn.recv(1024)

		qrCode = decode(Image.open(str(message)))
		qrCodeClean = str(qrCode[0].data).split("b\'")[1]
		qrCodeClean = str(qrCodeClean).split('\'')[0]
		identification, cli_otp = qrCodeClean.split("|")
		# print(type(identification))
		identification = int(identification)
		os.remove('./{}'.format(message))
		cli_otp = cli_otp.split("\'")[0]
		new_code = ''
		my_hash = ''
		user_founded = False

		for key, user in self.user_list.items():
			if int(identification) == key:
				# print('JA TEM AAAAA')
				new_code = ''
				for i in range(int(user[1]), int(cli_otp)):
					new_code = hashlib.sha256(user[0].encode())
					new_code = str(new_code.hexdigest())
				my_hash = hmac.new(pickle.dumps(new_code), pickle.dumps(qrCodeClean), hashlib.sha256)
				my_hash = str(my_hash.hexdigest())
				user[0] = new_code
				user[1] = cli_otp
				user_founded = True
				# print('CODE: {}\n HASH:{}'.format(new_code, my_hash))
				# break

		if user_founded == False:
			sconn.send(b'AuthUser')
			sconn.send(pickle.dumps(identification))

			response = sconn.recv(1024)

			if response == b'Yes':
				new_code = ''
				last_code = pickle.loads(sconn.recv(1024))
				server_otp = pickle.loads(sconn.recv(1024))
				# idt = int(identification)
				for i in range(int(server_otp), int(cli_otp)):
					new_code = hashlib.sha256(last_code.encode())
					new_code = str(new_code.hexdigest())
				my_hash = hmac.new(pickle.dumps(new_code), pickle.dumps(qrCodeClean), hashlib.sha256)
				my_hash = str(my_hash.hexdigest())
				# print('CODE: {}\n HASH:{}'.format(new_code, my_hash))
				# print('AAAAA')
				# cli_otp = cli_otp
				self.user_list[identification] = [new_code, cli_otp]

			else:
				print('User does not exists!')

		if my_hash == cli_hash:
			# print('Authentication successful!\n')
			# print(my_hash)
			# sconn.send(pickle.dumps(new_code))
			cconn.send(b'Auth')
		# pass
		else:
			print('Failed authentication')
			cconn.send(b'nAuth')


	def listen(self):
		# Cifra só na associação. Não na autenticação.
		'''
		Function to connect with server.
		'''
		

		context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.server_cert)
		context.load_cert_chain(certfile=self.turnstile_cert, keyfile=self.turnstile_key)

		while True:
			# try:
				
			# for i in range(0,10000): #Just to test some authentication requests
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sconn = context.wrap_socket(s, server_side=False, server_hostname=self.server_sni_hostname)
			sconn.connect((self.sip, self.sport))
			
			t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
			
			t.bind((self.tip, self.tport))
			
			t.listen(1)
			
			#print('aaaaaaaaaaaa')

			cconn, cli = t.accept()

			while True:
				self.requestAuth(sconn, cconn) #Call request list user functions.
			# cconn.close()

			break


if __name__ == "__main__":
	args = parseArguments()
	Turnstile = Turnstile(args.sip, int(args.sport), args.tip, int(args.tport))
	Turnstile.listen()