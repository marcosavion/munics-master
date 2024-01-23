import random
import secrets
import paho.mqtt.client as mqtt 
import time

#CONSTS
MQTT_IP_ADDRESS = ""
MQTT_PASSWORD = ""
MQTT_USER = ""
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60

USER_ID = b""


M = 3
N = Q = M * 3



class Alice():
    '''
    Class to store and create the MQTT connection
    '''
    def __init__(self, mqtt_ip_address ,mqtt_user, mqtt_password, mqtt_port, mqtt_keepalive, user_id):
        self.mqtt_ip_address = mqtt_ip_address
        self.mqtt_user = mqtt_user
        self.mqtt_password = mqtt_password
        self.mqtt_port = mqtt_port
        self.mqtt_keepalive = mqtt_keepalive
        self.user_id = user_id

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
        r = message.payload

        self.VectorCommitmentProcess(r)


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


    def publishMessage(self, recipient, message):
        '''
        This method publishes a particular message to the recipient's topic
        '''
        self.client.publish(recipient, message)
    
    def VectorCommitmentProcess(self, r):
        '''
        This is the main method to generate the vector commitment process
        '''
        #Generating b, c, the seed and the random number using this seed
        b = self.generateRandomCommitmentVector(M)
        c = self.generateC(b)
        seed_random_number = self.selectSeed(N)
        pseudorandomNumber = self.generateRandomNumberFromSeed(seed_random_number, r)

        #Calculating Gr, G0 and e
        Gr = self.generateGr(pseudorandomNumber,r)
        G0 = self.generateG0(pseudorandomNumber,r)
        e = self.calculateE(c,Gr)

        #Printing values
        print("-> s is: ")
        print("\t" + str(seed_random_number))

        print("-> b is: ")
        b =  "".join([str(letter) for letter in b])
        print("\t" + str(b))

        print("-> e is: ")
        print("\t" + str(e))

        print("-> G0 is: ")
        print("\t" + str(G0))

        #Printing seed with padding and in binary
        seed_binary = self.addBinaryPadding(self.toBinary(seed_random_number),N)
        print("-> seed_binary \n\t" + str(seed_binary))
        
        print("-> seed with padding \n\t" + str(self.addBinaryPadding(self.toBinary(seed_random_number),N)))

        time.sleep(2)
        
        #Sending all data to Bob
        print("\nSending all this information to Bob...")

        #b =  "111"
        self.sendAllToBob(seed_binary, b, e, G0, "MV37B")


    def generateRandomCommitmentVector(self, m: int) -> list:
        '''
        This method generates a random commitment vector
        '''

        print("Generating the random commitment vector of " + str(M) + " bits")
        
        commitmentVector = list()

        for _ in range(m):
            number = secrets.randbelow(2)
            commitmentVector.append(number)

        print("\nThe commitment vector is the following: \n\t" + str(commitmentVector))
        return commitmentVector
    

    
    def generateC(self, b: list) -> list():
        '''
        This method concatenates 3 times b in order to create c. 
        c = (b,b,b)

        Returns c
        '''

        c = list()
        for _ in range(3):
            for bit in b:
                c.append(bit)

        #Using list comprehension to transform int items of the list in strings
        c = "".join([str(letter) for letter in c])

        print("C is: \n\t" + str(c))

        return c
    
    def selectSeed(self, n):
        '''
        This method selects a seed of n bits
        '''
        seed_random_number = secrets.randbits(n)
        return seed_random_number

    def generateRandomNumberFromSeed(self, seed_random_number, r):
        '''
        This method is used to generate a pseudorandom number
        '''

        pseudorandomNumber = list()
        random.seed(seed_random_number)
        
        for _ in range(len(r)):
            pseudorandomNumber.append(random.randint(0,1))
            
        pseudorandomNumber = "".join([str(letter) for letter in pseudorandomNumber])

        return pseudorandomNumber
    
    def generateGr(self, pseudorandomNumber, r):
        '''
        This method generates Gr
        In words, takes G(s) and only selects the bits of Gi(s) where in ri is 1
        '''

        r = r.decode()
        gr = list()
        
        for i in range(len(r)):
            if (r[i] == "1"):
                gr.append(pseudorandomNumber[i])

        gr = "".join(gr)

        return gr

    
    def generateG0(self, pseudorandomNumber, r):
        '''
        This method generates G0
        In words, takes G(s) and only selects the bits of Gi(s) where in ri is 0
        '''

        r = r.decode()
    
        g0 = list()
        
        for i in range(len(r)):
            if (r[i] == "0"):
                g0.append(pseudorandomNumber[i])

        g0 = "".join(g0)

        return g0


    def calculateE(self, c, Gr):
        '''
        This method calculates E by doing the xor and returns it. The xor is calculated bitwise 
           -e = c xor Gr
        '''

        print("\nCalculating XOR")
        print("\tC  = \t" + str(c))
        print("\tGr = \t" + str(Gr))
        print("\t\t" + "---------")

        e = ""

        if len(c) == len(Gr):
            for i in range(len(c)):
                e += str(int(c[i])^int(Gr[i]))
            
        print("\te  = \t" + str(e) + "\n")
        return e

    
    def toBinary(self, number):
        '''
        This simple method only returns a given number in binary format
        '''
        return "{0:b}".format(number)

    def addBinaryPadding(self, numero_binario, longitud_deseada):
        '''
        This method is used to add padding to binary numbers in order to set the same length to all seeds
        '''
        if len(numero_binario) < longitud_deseada:
            padding = "0" * (longitud_deseada - len(numero_binario))
            numero_binario = padding + numero_binario
        return numero_binario


    def sendAllToBob(self, seed, b, e, G0, recipientTopic):
        total_message = str(seed) + b + e + G0
        self.publishMessage(recipientTopic, total_message)





if __name__ == '__main__':

    mqtt = Alice(MQTT_IP_ADDRESS,MQTT_USER, MQTT_PASSWORD, MQTT_PORT, MQTT_KEEPALIVE, USER_ID.decode('ascii'))

    mqtt.listenMessages()

    






    
