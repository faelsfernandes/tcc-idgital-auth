import socket
import ssl
import re
import pickle
import hashlib
import base64
from communication import *
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
from random import randint
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

class Server(Communication):

    #Communication server data.
    server_key = 'server.key'
    client_cert = 'client.pem'

    #Data.
    key_k = ''
    deviceData = ''
    key_m = ''
    serverRandomNumber = ''
    appRandomNumber = ''
    imei = ''
    masterKey = ''
    otpStatus = ''
    authenticationKey = ''

    def __init__(self):
        pass

    def genAuthenticationKey(self, otpStatus, key):
        for i in range(0,int(otpStatus)):
            key = hashlib.sha256(key.encode()).hexdigest()
        print("Authentication Key: " + key)
        return key

    def genMasterKey(self):
        '''
        Function that generate master key.
        '''
        self.masterKey = str(self.key_k) + str(self.key_m) + str(self.appRandomNumber) + str(self.serverRandomNumber) + str(self.imei)
        self.masterKey = hashlib.sha256(self.masterKey.encode()).hexdigest()
        print("MASTER KEY: " + self.masterKey)

    def genCodes(self):
        '''
        Function that generate 'tls', 'sms' and 'e-mail' codes.
        '''
        code1 = randint(100,999)
        code2 = randint(100,999)
        code3 = randint(100,999)
        print("tls_code: " + str(code1) + " sms_code: " + str(code2) + " email_code" + str(code3))
        return (code1, code2, code3)

    def receiveProofKeyM(self, conn, key_m):
        '''
        Function to check if key_m match on both sides.
        This function just receive random number and his hash from app.
        '''
        randNum = pickle.loads(conn.recv(1024)) #Receive random number.
        receivedHash = pickle.loads(conn.recv(1024)) #Receivce hash.
        decryptedRandNum = str(randNum)
        try: #Try to decrypted server number
            decrypted = int(self.decrypt(bytes(key_m, "utf-8"), decryptedRandNum, True))#Decrypt number and sum 1.
        except:
            print("Could not decrypt number")

        self.sendProofKeyM(conn, decrypted) #Call function to send the new hash to app.

    def sendProofKeyM(self, conn, randomNumber):
        '''
        Function to check if key_m match on both sides.
        This function generante a new hash and sent to the app check if key_m matches.
        '''
        proofHash = str(randomNumber + 1) #Sum 1 to generate a new hash.
        proofHash = hashlib.sha256(proofHash.encode()).hexdigest() #Get hash.
        conn.send(pickle.dumps(proofHash)) #Send hash to app.

    def sendServerData(self, key_m, conn):
        '''
        Function that send server random number to app.
        '''
        self.serverRandomNumber = randint(100000000,999999999) #Generate server random number.
        serverData = str(self.serverRandomNumber) #Convert to string.
        encrypted = self.encrypt(bytes(key_m, "utf-8"), bytes(serverData,"utf-8"), True) #Encrypt data.
        decrypted = self.decrypt(bytes(key_m, "utf-8"), encrypted, True) #Decrypt data just to test.
        decrypted = str(decrypted, "utf-8") #Convert bytes to string.
        conn.send(pickle.dumps(encrypted)) #Send encrypted data to server.

    def receiveDeviceData(self, conn):
        '''
        Function the devie data (IMEI, app random number)
        '''
        deviceData = pickle.loads(conn.recv(1024)) #Receive device data.
        decrypted = self.decrypt(bytes(self.key_k, "utf-8"), deviceData, True) #Decrypt data.
        decryptedData = str(decrypted, "utf-8")
        self.imei, self.appRandomNumber = decryptedData.split("|")
        # print("imei: " + self.imei)
        # print("App Random Number" + self.appRandomNumber)
        # # print("deviceData: " + deviceData + " Key_k: " + self.key_k)
        # print("Decrypted: " + self.deviceData)
    
    

    def connection(self):
        '''
        Function that estabelish connection with client
        '''
        addr = '127.0.0.1'
        port = 5567
        server_cert = 'server.pem'
        server_key = 'server.key'

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=self.server_cert, keyfile=self.server_key)
        context.load_verify_locations(cafile=self.client_cert)

        bindsocket = socket.socket()
        bindsocket.bind((self.addr, self.port))
        bindsocket.listen(5)

        while True:
            print("Waiting for client")
            newsocket, fromaddr = bindsocket.accept()
            print("Client connected: {}:{}".format(fromaddr[0], fromaddr[1]))
            conn = context.wrap_socket(newsocket, server_side=True)
            print("SSL established. Peer: {}".format(conn.getpeercert()))
            buf = b''  # Buffer to hold received client msg
            
            try:
                while True:
                    try:
                        msg = conn.recv(4096)
                        if re.search('RegisterRequest', msg.decode("utf-8")):
                            print("Registering...")
                            code1,code2,code3 = self.genCodes() #Generate the 3 codes
                            conn.send(pickle.dumps(code1)) #Send 'tls code'.
                            conn.send(pickle.dumps(code2)) #Send 'sms code'.
                            conn.send(pickle.dumps(code3)) #Send 'e-mail code'.
                            self.key_k = self.genKeyK(code1, code2, code3) #Generate temporary key: key_k.
                            self.receiveDeviceData(conn) #Receive device data from app.
                            self.key_m = self.genKeyM() #Generate temporary key: key_m.
                            self.receiveProofKeyM(conn,self.key_m)
                            self.sendServerData(self.key_m, conn) #Send server random number.
                            self.printData() #Just print all data.
                            self.genMasterKey() #Generate master key.
                            break
                        elif re.search('AuthenticationRequest', msg.decode("utf-8")):
                            self.otpStatus = pickle.loads(conn.recv(1024))
                            print("OTP STATUS: " + str(self.otpStatus))
                            if self.authenticationKey == '':
                                self.authenticationKey = self.genAuthenticationKey(self.otpStatus, self.masterKey)
                            else:
                                self.authenticationKey = self.genAuthenticationKey(self.otpStatus, self.authenticationKey)
                            
                            # receivedHash = pickle.loads(conn.recv(1024))
                            # print(type(receivedHash))
                            if self.authenticationKey == self.authenticationKey:
                                print("Authentication successful!")
                                conn.send(b'AuthenticationSucessful')
                            else:
                                print("Failed authentication")
                            break
                    except:
                        print("Error while registering")
                        break
            except:
                print("Closing connection")
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()

if __name__ == '__main__':
    server = Server()
    server.connection()