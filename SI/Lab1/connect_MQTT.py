import paho.mqtt.client as mqtt 

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


#CONSTS
MQTT_IP_ADDRESS = ""
MQTT_PASSWORD = ""
MQTT_USER = ""
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60

USER_ID = b""

class MQTTConnection():
    '''
    Class to store and create the MQTT connection
    '''
    def __init__(self, mqtt_ip_address ,mqtt_user, mqtt_password, mqtt_port, mqtt_keepalive, user_id, private_key = None):
        self.mqtt_ip_address = mqtt_ip_address
        self.mqtt_user = mqtt_user
        self.mqtt_password = mqtt_password
        self.mqtt_port = mqtt_port
        self.mqtt_keepalive = mqtt_keepalive
        self.user_id = user_id

        self.private_key = private_key

        self.client = mqtt.Client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message

        self.client.username_pw_set(username=self.mqtt_user, password=self.mqtt_password)
        self.client.connect(self.mqtt_ip_address, self.mqtt_port, self.mqtt_keepalive)


    def on_connect(self, client, userdata, flags, rc):
        '''
        This method is used to connect us to MQTT server.
        '''
        if rc == 0:
            print("\nSuccessful conection! Subscribing to your user_id... \n")
            self.client.subscribe(self.user_id)
        else:
            print("Unexpected MQTT connection error. returned code: " + str(rc))

        
    def on_message(self, client, userdata, message):
        '''
        This method is automatically executed when a message is received.
        '''
        #In order not to overload this method, I created another one to organize the functionality better
        self.splitAndDecrytpMessage(message.payload)

    def publishMessage(self, recipient, ciphertext):
        '''
        This method publishes a particular ciphertext to recipient
        '''
        self.client.publish(recipient, ciphertext)


    def listenMessages(self):
        '''
        This method is used to set up a listener and wait for incoming message.
        '''
        while True:
                self.client.loop_start()
                leave = input('\nPress enter to leave: \n')
                if leave == '':
                    self.client.loop_stop()
                    break


    def splitAndDecrytpMessage(self, ciphertext):
        '''
        This method splits the message in two parts:
            -Encrypted K
            -Encrypted message with that K

        So after that, it decrypts the k and then the message.
        '''
        
        symmetric_key_length = self.private_key.key_size // 8

        symmetric_encrypted_key = ciphertext[:symmetric_key_length]
        message_encrypted = ciphertext[symmetric_key_length:]

        #Firstly, we are going to decrypt the symmetric_encrypted_key with our private key
        symmectric_key = self.decrypt(symmetric_encrypted_key, self.private_key)
        
        #Secondly, we are going to decrypt the message using this symmetric_key
        plaintext_encoded = self.decryptMessage(symmectric_key, message_encrypted)

        #Call decodeAndRelay function to see if we are the last node or not.
        self.decodeAndRelay(plaintext_encoded)


    def decrypt(self, encrypted, private_key):
        '''
        This method decrypts the key by using our private_key
        '''

        symmectric_key = private_key.decrypt(encrypted, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
        return symmectric_key  

    def decryptMessage(self, key, ciphertext):
        '''
        This method decrypts the ciphertext by using the key
        '''
        aesgcm = AESGCM(key)
        nonce = key
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext 


    def id_from_message(self,message):
        '''
        This method removes padding and select only the id of the message
        '''
        return message[:5].strip(b'\x00').decode('ascii')
    

    def decodeAndRelay(self, encoded_plaintext):
        '''
        This method decodes the message and relays it if we are not the recipient.
        '''
        #Get the start of the message and remove the padding
        next_hop = self.id_from_message(encoded_plaintext[:5])
        #Removes this part from the plaintext
        encoded_plaintext = encoded_plaintext[5:]

        if next_hop == "END" or next_hop == "end":
            #We are the recipient (the last hop)
            source = self.id_from_message(encoded_plaintext[:5])
            message = encoded_plaintext[5:].decode('ascii')

            print("\nYou have just received a message!")
            print("Source: " + str(source))
            print("Message: " + str(message))

        else:
            #We are not the recipient
            print("Relaying a message to " + str(next_hop))
            self.publishMessage(next_hop,encoded_plaintext)
            

            


        