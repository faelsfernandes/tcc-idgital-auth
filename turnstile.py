from PIL import Image
from pyzbar.pyzbar import decode
import pyqrcode
import qrtools
import socket
import ssl
import re
import pickle
import hmac
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
	# client_cert = 'client.pem'
	# client_key = 'client.key'

	user_list = {}

	def __init__(self, sip, sport, tip, tport):
		self.sip = sip
		self.sport = sport
		self.tip = tip
		self.tport = tport	

	def genAuthenticationKey(self, cli_otp, server_otp, key):
		for i in range(0,int(cli_otp) - int(server_otp)):
			key = hashlib.sha256(key.encode()).hexdigest()
		print("Authentication Key: " + key)
		return key

	def requestAuth(self, sconn, cconn):
		# while True:
		# try:
		if cconn.recv(1024) == b'AuthMe':
			print('AUTHING')
			message = pickle.loads(cconn.recv(1024))
			qrCode = decode(Image.open(message))
			qrCodeClean = str(qrCode[0].data).split("b\'")[1]
			identification, cli_otp = qrCodeClean.split("|")
			cli_otp = cli_otp.split("\'")[0]
			cli_auth = pickle.loads(cconn.recv(1024))
			print('IDENTIFICATION: {}\n OTP: {}\n HMAC: {}'.format(identification, cli_otp, cli_auth))
			sconn.send(b'AuthUser')
			# print('aaaaaaaaa')
			sconn.send(pickle.dumps(identification))
			if sconn.recv(1024) == b'Yes':
				server_auth = pickle.loads(sconn.recv(1024))
				server_otp = pickle.loads(sconn.recv(1024))	
				server_auth = self.genAuthenticationKey(cli_otp, server_otp, cli_auth)
				server_otp = int(server_otp) + int(cli_otp) - int(server_otp)
				sconn.send(pickle.dumps(server_auth))				
				sconn.send(pickle.dumps(server_otp))
				print(cli_auth)
				print(server_auth)
				if cli_auth == server_auth:
					print('AUTENTICADOOOO AA')


			else:
				print("User not exists!")
				
			

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
			
			t.bind((self.tip, 4444))
			
			t.listen(1)
			print('aaaaaaaaaaaa')


			while True:
				cconn, cli = t.accept()
				print("Sending: AuthUser")
				self.requestAuth(sconn, cconn) #Call request list user functions.
				print("#####################\n")
				# break
			# except:
			# 	print("Unable to receive")
			break


if __name__ == "__main__":
	args = parseArguments()
	Turnstile = Turnstile(args.sip, int(args.sport), args.tip, int(args.tport))
	Turnstile.listen()