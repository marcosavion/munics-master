import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.padding import PKCS7
import math
import sys



def askDevices() -> int:
    '''
    This method asks user how many devices he/she wants to use
    Returns the number of devices
    '''

    devices = input("\nSelect how many device you want to use: ")
    return int(devices)

def askAttackedDevice(available_nodes: list, n_device: int) -> list:
    '''
    This method asks user which devices are corrupted/attacked
    Returns a list of ids
    '''
    attacked_devices_list = list()

    id_devices = calculateLeaves(available_nodes, n_device)

    print("\nThe available devices are the following: " + str(id_devices))

    exit = False

    while(not exit):
        attacked_device = input("\nSelect one or a list of attacked device or hit enter to exit: ")

        if attacked_device == "":
            exit = True
            break
        
        else:
            if(int(attacked_device) in id_devices):     
                attacked_devices_list.append(int(attacked_device))
                print("Attacked devices: " + str(attacked_devices_list))

    return attacked_devices_list


def askMessage() -> str:
    '''
    This method asks user which message he wants to encrypt
    Returns the message
    '''
    message = input("\nWrite the message that you want to encrypt: ")
    return message

def askDeviceToDecrypt(devices_list: list) -> int:
    '''
    This method asks user with which device she/he wants to decrypt the message
    Returns the id of the device which user wants to use
    '''

    selected_device = input("\nSelect the device that you want to use to decrypt the message or hit enter to exit: ")

    if selected_device == "":
            return ""
    
    while((int(selected_device) not in devices_list)):
        selected_device = input("\nSorry, this id is not valid. Please select the device that you want to use to decrypt the message or hit enter to exit: ")
        
        if selected_device == "":
            return ""
        
    return int(selected_device)
    



def calculateLeaves(available_nodes, n_device) -> list:
    '''
    This method calculates the leaves and returns the identifiers of these
    '''
    return available_nodes[-n_device:]


def calculateParentById(id: int) -> list:
    '''
    Recursive method.
    This method returns all the id parents of a particular id
    '''

    list_of_parents = list()

    if(id!=1):
        id_parent = math.floor(id/2)
        list_of_parents = [id] + calculateParentById(id_parent)
    else:
        list_of_parents.append(id)
        
    return list_of_parents


def calculateParentByIdList(id_list: list) -> list:
    '''
    This method returns all the id parents of a particular id
    '''

    parent_id_list = list()

    for node in id_list:
        parent_id_list = parent_id_list + calculateParentById(node)

    #Remove repeated elements
    parent_id_list = list(set(parent_id_list))

    return parent_id_list


def calculateCover(id_list: list, list_of_parents: list, limit: int) -> list():
    '''
    This method returns the cover of a given id
    '''
    cover = list()

    if not isinstance(id_list,list):
        id_list = [id_list]
    
    for id in id_list:
        if(id!=1 and id<limit):
            #If id is even
            if(id % 2 == 0):
                cover.append(id+1)
            else:
                cover.append(id-1)

        for node_id in list_of_parents:
            if(node_id!=1 and node_id<limit):
                #If id is even
                if(node_id % 2 == 0):
                    cover.append(node_id+1)
                else:
                    cover.append(node_id-1)

    #Remove the repeated elements
    cover = list(set(cover))

    #Remove the invalid elements
    valid_cover = list()

    for node in cover:
        if node not in list_of_parents:
            valid_cover.append(node)

    return valid_cover


def calculateValidPath(path_to_decrypt, broken_path_list) -> list():
    '''
    This method validates all the possible node to decrypt in order to verify that anyone was attacked
    Returns a list of valid nodes
    '''

    valid_path_to_decrypt = list()

    for node in path_to_decrypt:
        if node not in broken_path_list:
            valid_path_to_decrypt.append(node)

    return valid_path_to_decrypt


def generateTotalNodes(n_devices: int) -> list():
    '''
    This method calculates the number of total nodes that we have to use to create the binary tree
    '''
    n_nodos = 2 * n_devices - 1

    exp = 1
    while(n_nodos>2**exp):
        exp +=1
    
    n_nodos = 2**exp

    nodes = list()

    no_nodes = int(n_nodos/2) - n_devices

    for n_node in range(1,n_nodos-no_nodes,1):
        nodes.append(n_node)

    return nodes




#-----------------------------ENCRYPTION--------------------
def generateRandomKey():
    # Generate a random 128-bit IV.
    iv = os.urandom(16)
    return iv

def generateKeyNodes(n_nodes):
    #This method generates a random key for each node

    #Create the key list
    key_list = []

    for _ in range(n_nodes):
        key = generateRandomKey()
        key_list.append(key)

    return key_list

def addPaddingToMessage(msg: str) -> bytes:
   '''
   This method add padding to the given message and returns it
   '''
   message_bytes = msg.encode('ascii')

   pad = PKCS7(algorithms.AES.block_size).padder()
   message_with_padding = pad.update(message_bytes) + pad.finalize()

   return message_with_padding




def encrypt(key, plaintext):
    '''
    This method encrypts the particular plaintext using the given key
    '''
    # Generate a random 128-bit IV.
    iv = os.urandom(16)
    # Construct an AES-128-CBC Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
    backend=default_backend()
    ).encryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext)

def encryptKeysAndMessage(main_key, keys, cover, message_with_padding):
    '''
    This method encrypts the message and the main key to all nodes of the cover.
    This procedure is described in the document
    '''
    encryption_list = list()

    for i in range(len(cover)):
        
        encryption_list.append(encrypt(keys[cover[i] - 1], main_key))

    encryption_list.append(encrypt(main_key, message_with_padding))

    return encryption_list



def decrypt(key, iv, ciphertext):
    # Construct a Cipher object, with the key, iv
    decryptor = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
    backend=default_backend()
    ).decryptor()
    # Decryption gets us the plaintext.
    return decryptor.update(ciphertext) + decryptor.finalize()


def try_to_decrypt(path_to_decrypt, encryption_list, cover:list, iv, c) -> str:
    '''
    This method tries to decrypt the message using the given path of nodes
    For every node of the path, we are going to check if we are able to decrypt the message
    '''

    for node in path_to_decrypt:

        if(node in cover):
            #If the node is in cover -> then decrypt the message

            index_cover_id = cover.index(node)

            iv_node_cover = encryption_list[index_cover_id][0]
            ciphertext_node_cover =  encryption_list[index_cover_id][1]

            decryption_node_key = decrypt(keys[int(node)-1], iv_node_cover, ciphertext_node_cover)

            decrypted_message = decrypt(decryption_node_key, iv, c)

            if decrypted_message == message_with_padding:
                print("\nDecrypting the message with node " + str(node))
                #Get the unpadder to remove the padding from the message
                unpadder = PKCS7(algorithms.AES.block_size).unpadder()
                message_without_padding = (unpadder.update(decrypted_message) + unpadder.finalize()).decode('ascii')
                
                return message_without_padding


    return "-1"




#----------------------------------MAIN--------------------------------------
if __name__ == '__main__':
    #Create a the main random key
    main_key = generateRandomKey()

    #Create each node key and store it in a list
    #key_node_list = generateKeyNodes()
    
    n_device = askDevices()

    total_node_list = generateTotalNodes(n_device)

    devices_list = calculateLeaves(total_node_list, n_device)

    attacked_devices = askAttackedDevice(total_node_list, n_device)

    message = askMessage()

    message_with_padding = addPaddingToMessage(message)

    keys = generateKeyNodes(total_node_list[-1])

    encryption_list = []

    broken_path_list = calculateParentByIdList(attacked_devices)
    
    print("\nThe attacked nodes are the following")
    print("\t" + str(broken_path_list))

    cover = calculateCover(attacked_devices, broken_path_list, devices_list[-1])

    print("\nThe cover is")
    print("\t" + str(cover))

    #With the cover nodes, encrypt the message and each key
    encryption_list = encryptKeysAndMessage(main_key, keys, cover, message_with_padding)

    exit = False

    while (not exit):
        decrypt_device_id = askDeviceToDecrypt(devices_list)

        if(decrypt_device_id == ""):
            exit = True
            print("Byeee")
            sys.exit(0)

        path_to_decrypt = calculateParentById(decrypt_device_id)

        valid_path_to_decrypt = calculateValidPath(path_to_decrypt, broken_path_list)

        #Get the iv, random number used to encrypt the message, and the ciphertext
        iv = encryption_list[-1][0]
        c = encryption_list[-1][1]

        result_decryption = try_to_decrypt(valid_path_to_decrypt, encryption_list, cover, iv, c)

        if result_decryption == "-1":
            print("You cannot decrypt the message by using this node")
        else:
            print("The message was decrypted successfully")
            print("\tmessage: " + str(result_decryption))




    



