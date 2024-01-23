import cryptography

import paho.mqtt.client as mqtt

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from connect_MQTT import MQTTConnection

#CONSTS
MQTT_IP_ADDRESS = ""
MQTT_PASSWORD = ""
MQTT_USER = ""
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60

END = b"end"
ANON = b"none"
USER_ID = b""


#Dictionary with all public keys
pubkey_dictionary = {

}


def askMsg() -> str:
    '''
    This method asks the user for the message that he/she wants to send.
    '''
    user_message = input("\What is the message that you want to send?: ")
    return user_message


def askAnonymity() -> bool:
    '''
    This method asks user if he/she wants to send the message anonymously
    '''
    user_anonymity = input("Do you want to send the message anonymously (y/n): ")

    if (user_anonymity == 'y' or user_anonymity == "yes"):
        return True
    else:
        return False

def askUser() -> bytes:
    '''
    This method asks the user who is the recipient and if he/she wants to send the message anonymously.

    Returns the encoded message with padding -> (end + none|MV37 + user_message)
    '''

    m = ""
    user_message = askMsg() 
    user_anonymity  = askAnonymity()

    if(user_anonymity):
        #If the user wants to send the message anonymously
        m = id_padding(b"none") + id_padding(user_message.encode('ascii'))
    else:
        m = id_padding(USER_ID) + id_padding(user_message.encode('ascii'))
   
    #Concatenating the b"end" with (source||none, m)
    m = id_padding(END) + m

    return m



def askRecipient() -> str:
    '''
    This method asks user who is the recipient and validates his answer.

    Returns the recipient
    '''

    invalid_recipient = True

    print("Choose a recipient for this list\n")
    print(str(list(pubkey_dictionary.keys())))

    while (invalid_recipient):
        recipient = input("\nType a recipient: ")

        if(recipient in list(pubkey_dictionary.keys())):
            invalid_recipient = False
        else:
            print("This recipient ID is invalid")
        
    return recipient


def askPath() -> list():
    '''
    This method asks user for the path which he/she wants to use to send the message

    Returns: a list named path with all hops that the user wants to use.    
    '''

    continue_path = True
    path = list()

    print("\nChoose the path that you want to use to send your message")
    print("All available host are the following: \n")
    print(list(pubkey_dictionary.keys()))

    while continue_path:
        hop = input("\nChoose the next hop or hit enter button to finish this process: ")
        
        if(hop in pubkey_dictionary.keys()):
            path.append(hop)
            print(path)
        elif(hop.strip() == ""):
            continue_path = False
        else:
            print("The hop: " + hop + " is not a valid hop")

    print("\nThis is the path chosen: " + str(path))

    return path





def getPublicKey(id) -> str:
    '''
    This is a simple method to return the public key from a id by concatenating "ssh-rsa" previously
    '''
    return "ssh-rsa " + pubkey_dictionary.get(id)
    

def id_padding(id) -> bytes:
    '''
    This function returns a particular message with padding, specially ids.
    '''
    return (b'\x00' * (5-len(id)) + id)


def generateRandomKey() -> bytes:
    '''
    This method generates a 128 bits random key and returns it
    '''
    key = AESGCM.generate_key(bit_length=128)
    return key

def encryptMessage(key: bytes, message: bytes) -> bytes:
    '''
    This method encrypts the message with this particular key
    '''
    aesgcm = AESGCM(key)
    nonce = key
    ciphertext = aesgcm.encrypt(nonce, message, None)
    return ciphertext


# RSA encryption function
def rsa_encrypt(public_key: str, message):
    '''
    This method loads my public_key and and encrypts a particular message with that

    Returns the ciphertext.
    '''

    public_key = serialization.load_ssh_public_key(public_key.encode('ascii'), backend=default_backend())

    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))




def nestedHybridEncryption(hop_path: list, ciphertext, recipient):
    '''
    This method is used when the user suggest to use hops
    '''

    ciphertext = id_padding(recipient.encode('ascii')) + ciphertext

    for i in range(len(hop_path)):
        #Generating a new random key for each hop
        key = generateRandomKey()

        #Encrypt the message with this key
        encrypted_message = encryptMessage(key, ciphertext)
        
        #Getting the public key of this hop
        public_key_hop = getPublicKey(hop_path[i])

        #Encrypt the key with this public key
        rsa_key = rsa_encrypt(public_key_hop, key)

        ciphertext = rsa_key + encrypted_message

        #Checking if hop is the last one
        if i != (len(hop_path)-1):
            #If it is not the last one, add its id
            ciphertext = id_padding(str(hop_path[i]).encode('ascii')) + ciphertext

    
    return ciphertext



if __name__ == '__main__':

    mqtt = MQTTConnection(MQTT_IP_ADDRESS, MQTT_USER, MQTT_PASSWORD, MQTT_PORT, MQTT_KEEPALIVE, USER_ID)

    key = generateRandomKey()

    m_plaintext = askUser()

    message_encrypted = encryptMessage(key, m_plaintext)

    recipient = askRecipient()

    hop_path = askPath()

    pubkey_recipient = getPublicKey(recipient)

    #Encripting with the recipient public key
    rsa_key = rsa_encrypt(pubkey_recipient,key)

    ciphertext = rsa_key + message_encrypted

    if hop_path == []:
        print("Sending a message without hops")
        mqtt.publishMessage(recipient, ciphertext)

    else:
        print("Sending a message with hops")
        ciphertext = nestedHybridEncryption(hop_path, ciphertext, recipient)
        mqtt.publishMessage(hop_path[-1], ciphertext)


        
    




