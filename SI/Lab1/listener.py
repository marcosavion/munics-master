from connect_MQTT import MQTTConnection

import paho.mqtt.client as mqtt

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MQTT_IP_ADDRESS = ""
MQTT_PASSWORD = ""
MQTT_USER = ""
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60

USER_ID = b""

def loadMyPrivateKey():
    '''
    This method reads the private key and stores it.
    '''
    with open("SI_key", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    return private_key
   

if __name__ == '__main__':

    private_key = loadMyPrivateKey()

    mqtt = MQTTConnection(MQTT_IP_ADDRESS,MQTT_USER, MQTT_PASSWORD, MQTT_PORT, MQTT_KEEPALIVE, USER_ID.decode('ascii'), private_key)

    mqtt.listenMessages()
