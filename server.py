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
    kt1 = ''
    deviceData = ''
    kt2 = ''
    server_rand = ''
    app_rand1 = ''
    imei = ''
    master_key = ''
    otpStatus = ''
    authenticationKey = ''

    def __init__(self):
        pass

    def genAuthenticationKey(self, otpStatus, key):
        for i in range(0,int(otpStatus)):
            key = hashlib.sha256(key.encode()).hexdigest()
        print("Authentication Key: " + key)
        return key

    def genmaster_key(self):
        '''
        Function that generate master key.
        '''
        self.master_key = str(self.kt1) + str(self.kt2) + str(self.app_rand1) + str(self.server_rand) + str(self.imei)
        self.master_key = hashlib.sha256(self.master_key.encode()).hexdigest()
        print("MASTER KEY: " + self.master_key)

    def genCodes(self):
        '''
        Function that generate 'tls', 'sms' and 'e-mail' codes.
        '''
        code1 = randint(100,999)
        code2 = randint(100,999)
        code3 = randint(100,999)
        print("tls_code: " + str(code1) + " sms_code: " + str(code2) + " email_code" + str(code3))
        return (code1, code2, code3)

    def receiveProofkm(self, conn, kt2):
        '''
        Function to check if kt2 match on both sides.
        This function just receive random number and his hash from app.
        '''
        randNum = pickle.loads(conn.recv(1024)) #Receive random number.
        receivedHash = pickle.loads(conn.recv(1024)) #Receivce hash.
        decryptedRandNum = str(randNum)
        try: #Try to decrypted server number
            decrypted = int(self.decrypt(bytes(self.master_key, "utf-8"), decryptedRandNum, True))#Decrypt number and sum 1.
            print("MASTER KEY AUTHENTICATED")
        except:
            print("Could not decrypt number")

        self.sendProofkm(conn, decrypted) #Call function to send the new hash to app.

    def sendProofkm(self, conn, randomNumber):
        '''
        Function to check if kt2 match on both sides.
        This function generante a new hash and sent to the app check if kt2 matches.
        '''
        proofHash = str(randomNumber + 1) #Sum 1 to generate a new hash.
        proofHash = hashlib.sha256(proofHash.encode()).hexdigest() #Get hash.
        conn.send(pickle.dumps(proofHash)) #Send hash to app.

    def sendServerData(self, kt2, conn):
        '''
        Function that send server random number to app.
        '''
        self.server_rand = randint(100000000,999999999) #Generate server random number.
        serverData = str(self.server_rand) #Convert to string.
        encrypted = self.encrypt(bytes(kt2, "utf-8"), bytes(serverData,"utf-8"), True) #Encrypt data.
        decrypted = self.decrypt(bytes(kt2, "utf-8"), encrypted, True) #Decrypt data just to test.
        decrypted = str(decrypted, "utf-8") #Convert bytes to string.
        conn.send(pickle.dumps(encrypted)) #Send encrypted data to server.

    def receiveDeviceData(self, conn):
        '''
        Function the devie data (IMEI, app random number)
        '''
        deviceData = pickle.loads(conn.recv(1024)) #Receive device data.
        decrypted = self.decrypt(bytes(self.kt1, "utf-8"), deviceData, True) #Decrypt data.
        decryptedData = str(decrypted, "utf-8")
        self.imei, self.app_rand1 = decryptedData.split("|")
        # print("imei: " + self.imei)
        # print("App Random Number" + self.app_rand1)
        # # print("deviceData: " + deviceData + " kt1: " + self.kt1)
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
                            self.kt1 = self.gen_kt1(code1, code2, code3) #Generate temporary key: kt1.
                            self.receiveDeviceData(conn) #Receive device data from app.
                            self.kt2 = self.gen_kt2() #Generate temporary key: kt2.
                            self.sendServerData(self.kt2, conn) #Send server random number.
                            self.printData() #Just print all data.
                            self.genmaster_key() #Generate master key.
                            self.receiveProofkm(conn,self.kt2)
                            break
                        elif re.search('AuthenticationRequest', msg.decode("utf-8")):
                            self.otpStatus = pickle.loads(conn.recv(1024))
                            print("OTP STATUS: " + str(self.otpStatus))
                            if self.authenticationKey == '':
                                self.authenticationKey = self.genAuthenticationKey(self.otpStatus, self.master_key)
                            else:
                                self.authenticationKey = self.genAuthenticationKey(self.otpStatus, self.authenticationKey)
                            
                            # receivedHash = pickle.loads(conn.recv(1024))
                            # print(type(receivedHash))
                            if self.authenticationKey == self.authenticationKey:
                                print("Authentication successful!")
                                conn.send(b'AuthenticationSucessful')
                                self.authenticationKey = ''
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