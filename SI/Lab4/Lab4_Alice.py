from time import sleep
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import paho.mqtt.client as mqtt 
import threading

ROOT_KEY = b'\xb6\x99\xa4\xae2i\x1d,\xb7\x1fO\x93\x7f\x08)\xbd'

#CONSTS
MQTT_IP_ADDRESS = ""
MQTT_PASSWORD = ""
MQTT_USER = ""
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60

USER_ID = ""


class MQTTConnection():
    '''
    Class to store and create the MQTT connection
    '''
    def __init__(self, mqtt_ip_address, mqtt_user, mqtt_password, mqtt_port, mqtt_keepalive, user_id):
        self.mqtt_ip_address = mqtt_ip_address
        self.mqtt_user = mqtt_user
        self.mqtt_password = mqtt_password
        self.mqtt_port = mqtt_port
        self.mqtt_keepalive = mqtt_keepalive
        self.user_id = user_id

        self.private_key = None
        self.public_key = None

        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        self.client.username_pw_set(username=self.mqtt_user, password=self.mqtt_password)
        self.client.connect(self.mqtt_ip_address, self.mqtt_port, self.mqtt_keepalive)

        self.rootKey = ROOT_KEY

        self.publicKeyBob = None

        #Bool that indicates if it is the first time
        self.firstTime = True


    def on_connect(self, client, userdata, flags, rc):
        '''
        This method is used to connect us to MQTT server.
        '''
        if rc == 0:
            print("\nSuccessful connection! Subscribing to your user_id... \n")
            self.client.subscribe(self.user_id)
        else:
            print("Unexpected MQTT connection error. returned code: " + str(rc))

        
    def on_message(self, client, userdata, message: mqtt.MQTTMessage):
        '''
        This method is automatically executed when a message is received.
        '''

        #Parse the message
        message = message.payload
        messageParts = message.decode().split(".",1)
        protocol = messageParts[0]
        message = messageParts[1].encode('latin1')

        #If the message is a key
        if(protocol=="0"):
            if(self.firstTime):
                #Generate the public and private keys
                self.private_key, self.public_key = self.GENERATE_DH()

                #Set and retrieve the Bob public key
                self.publicKeyBob = X25519PublicKey.from_public_bytes(message)

                #Set the shared key
                self.sharedKey = self.DH(publicKeyOtherNode=self.publicKeyBob)

                print("\nNew shared key established: ")
                print("\t" + str(self.sharedKey) + "\n")

                sleep(0.5)

                self.publishMessage("MV37.bob", self.public_key.public_bytes_raw(), isKey=True)

                self.firstTime = False

        else:
            #Divide the message in two: the bob public key and the encrypted message
            newPublicKey = message[0:32]
            encrypted_msg = message[32:]

            #Generate the rootKey and changeKey
            nextRootKey, changeKey = self.KDF_RK(self.getSharedKey())

            self.rootKey = nextRootKey

            #Generate the messageKey and the next Chain key 
            messageKey, nextChainKey = self.KDF_CK(changeKey)

            self.changeKey = nextChainKey

            #Decrypt the message by using the messageKey 
            decrypted_msg = self.DECRYPT(messageKey, encrypted_msg)

            print("Bob: " + decrypted_msg.decode())

            #Update the shared key
            #Get the public key received
            self.publicKeyBob = X25519PublicKey.from_public_bytes(newPublicKey)

            #Generate the new shared key
            self.sharedKey = self.DH(publicKeyOtherNode=self.publicKeyBob)
            

    def GENERATE_DH(self) -> tuple[X25519PrivateKey, X25519PublicKey]:
        '''
        This method generates a new private and public key and set it 
        '''
        #Generates the new private key
        newPrivateKey = self.generatePrivateKey()
        self.setPrivateKey(newPrivateKey)

        #Generates the new public key
        newPublicKey = self.generatePublicKey(newPrivateKey)
        self.setPublicKey(newPublicKey)

        return newPrivateKey, newPublicKey


        
    def DH(self, publicKeyOtherNode: X25519PublicKey) -> bytes:
        '''
        This method generated the shared key from the other node public key
        '''
        sharedKey = self.getPrivateKey().exchange(publicKeyOtherNode)

        return sharedKey


    def KDF_RK(self, sharedKey: bytes) -> tuple[bytes(), bytes()]:
        '''
        Perform shared key derivation by using the rootkey as salt

        SHA-256 is recommended in the specification
        '''
        derivatedKey = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=self.rootKey,
            info=b'root key derivation',
        ).derive(sharedKey)

        nextRootKey = derivatedKey[0:32]
        changeKey = derivatedKey[32:]

        return nextRootKey, changeKey
    
    def KDF_CK(self, changeKey: bytes()) -> tuple[bytes(), bytes()]:
        '''
        This method generate the messageKey and the next ChainKey
        '''
        h1 = hmac.HMAC(changeKey, hashes.SHA256(), backend=default_backend())
        h1.update(bytes([0x01]))
        h2 = hmac.HMAC(changeKey, hashes.SHA256(), backend=default_backend())
        h2.update(bytes([0x02]))

        self.messageKey = h1.finalize()
        self.nextChainKey = h2.finalize()

        return self.messageKey, self.nextChainKey
    

    def ENCRYPT(self, messageKey, plaintext):
        '''
        This method encrypts the message by using the messageKey
        '''
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x00" * 32,
            info=b"encrypt_decrypt message",
            backend=default_backend()
        )
        key_material = hkdf.derive(messageKey)
        encryption_key, iv = key_material[:16], key_material[16:32]

        # Encryption
        cipher = AESGCM(encryption_key)
        ciphertext = cipher.encrypt(iv, plaintext, None)

        return ciphertext
    

    
    def DECRYPT(self, messageKey, ciphertext):
        '''
        This method decrypts the message by using the messageKey
        '''
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"\x00" * 32,
            info=b"encrypt_decrypt message",
            backend=default_backend()
        )
        key_material = hkdf.derive(messageKey)
        encryption_key, iv = key_material[:16], key_material[16:32]

        # Decrypts
        cipher = AESGCM(encryption_key)
        plaintext = cipher.decrypt(iv, ciphertext, None)

        return plaintext



    def writeMessage(self, recipient: str) -> None:
        '''
        This method asks user what he/she wants to send to the other node
        '''
        msg = input("")  

        #Generate a new Root Key and changeKey
        nextRootKey, changeKey = self.KDF_RK(self.getSharedKey())

        self.rootKey = nextRootKey

        #Generate the messageKey and the next chainKey from changeKey
        messageKey, nextChainKey = self.KDF_CK(changeKey)

        self.changeKey = nextChainKey

        encrypted_msg = self.ENCRYPT(messageKey, msg.encode('ascii'))

        self.publishMessage(recipient, encrypted_msg, False)
    
    
    def publishMessage(self, recipient: str, ciphertext: bytes, isKey: bool, firstTime: bool = False) -> None:
        '''
        This method publish a particular ciphertext to recipient
        '''
        ciphertextStr = ciphertext.decode('latin1')

        if(isKey):
            #Add a 0 at the beggining of the message
            msgToSend = "0." + ciphertextStr

        else:
            #Generate the news private and public key
            self.private_key, self.public_key = self.GENERATE_DH()

            #Generate the new shared Key
            self.sharedKey = self.DH(publicKeyOtherNode=self.publicKeyBob)

            public_key_str = self.public_key.public_bytes_raw().decode('latin1')

            #Add a 0 at the beggining of the message
            msgToSend = "1." + public_key_str + ciphertextStr 

        self.client.publish(recipient, msgToSend)


    def listenMessages(self):
        '''
        This method is used to set up a listener and wait for incoming message.
        '''
        while(True):
            self.client.loop_start()

            t1 = threading.Thread(target=self.writeMessage, args=("MV37.bob",))
            t1.start()
            t1.join()

    
    def generatePrivateKey(self) -> X25519PrivateKey:
        '''
        This method generate a new private key
        '''
        privateKey = X25519PrivateKey.generate()

        self.setPrivateKey(private_key=privateKey)
        
        return privateKey
    

    def generatePublicKey(self, privateKey: X25519PrivateKey) -> X25519PublicKey:
        '''
        This method generates a new public key
        '''
        publicKey = self.getPrivateKey().public_key()

        self.setPublicKey(publicKey)

        return publicKey
    

    def getPublicKey(self) -> X25519PublicKey:
        '''
        Returns the current public key
        '''
        return self.public_key

    def setPublicKey(self, public_key: X25519PublicKey) -> None:
        '''
        Sets the new public key
        '''
        self.public_key = public_key

    def getPrivateKey(self) -> X25519PrivateKey:
        '''
        Returns the current private key
        '''
        return self.private_key

    def setPrivateKey(self, private_key: X25519PrivateKey) -> None:
        '''
        Sets the new private key
        '''
        self.private_key = private_key

    def getSharedKey(self) -> bytes:
        '''
        Returns the current shared key
        '''
        return self.sharedKey
    
    def setSharedKey(self, sharedKey: bytes) -> None:
        '''
        Sets the new shared key
        '''
        self.sharedKey = sharedKey



        



if __name__ == '__main__':


    mqttConnection = MQTTConnection(mqtt_ip_address=MQTT_IP_ADDRESS,mqtt_user=MQTT_USER,mqtt_password=MQTT_PASSWORD,mqtt_port=MQTT_PORT,mqtt_keepalive=MQTT_KEEPALIVE, user_id=USER_ID)
    
    mqttConnection.listenMessages()


