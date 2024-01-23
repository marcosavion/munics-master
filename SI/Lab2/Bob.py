import random
import secrets
import paho.mqtt.client as mqtt 

#CONSTS
M = 3
N = Q = M * 3


#CONSTS
MQTT_IP_ADDRESS = ""
MQTT_PASSWORD = ""
MQTT_USER = ""
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60

USER_ID = b""

#R = b'000010101110101001110001011101111101000110000110011110110000'


class Bob():
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

        self.verifyAll(message.payload)

    def publishMessage(self, recipient, message):
        '''
        This method publishes a particular message to the recipient's topic
        '''
        self.client.publish(recipient, message)

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


    def verifyAll(self, message: str) -> None:
        '''
        This method verifies all fields
        '''
        print("Bob has just received a message from Alice!")

        #Split the message into seed, b, e from alice and G0 from alice
        seed, b, e_alice, G0_alice = self.splitMessage(message)
        #Transform the seed in a dec number
        seed_number = self.binaryToDec(seed)

        pseudorandomNumber = self.generateRandomNumberFromSeed(seed_number,2*Q)

        Gr = self.generateGr(pseudorandomNumber,self.getLastR())
        c = self.generateC(b)
        e = self.calculateE(c,Gr)

        #Hay que verificar si la e calculada nuestra es la misma que la que nos paso Alice
        print("Verifying all the fields")
        if(self.compare(e,e_alice)):
            print("\t-E is correct")
        else:
            print("\t-E is NOT correct!!!!")

        G0 = self.generateG0(pseudorandomNumber,self.getLastR())

        if(self.compare(G0_alice, G0)):
            print("\t-G0 is correct")
        else:
            print("\t-G0 is INCORRECT!!!")

        
    def splitMessage(self, message: str) -> list():
        '''
        This method recieves a message and splits it into seed, b, e and G0 and returns all values
        '''
        print("\nAlice has sent to bob:")
        seed = message[:N].decode('ascii')
        print("->seed = \n\t" +str(seed))
        b = message[N:N+M].decode('ascii')
        print("->b = \n\t" + str(b))
        e = message[N+M:N+M+3*M].decode('ascii')
        print("->e = \n\t" + str(e))
        G0 = message[N+M+3*M : N+M+3*M+Q].decode('ascii')
        print("->G0 = \n\t" + str(G0))

        return seed, b, e, G0
    
    
    def generateRandomNumberFromSeed(self, seed_random_number: int, length: int) -> str:
        '''
        This method generates a random number by using a particular see
        '''
        randomNumberList = list()

        #Setting the seed that we want to use
        random.seed(seed_random_number)
        
        for _ in range(length):
            #Selects a number: 0 or 1 and adds that to toret list
            randomNumberList.append(random.randint(0,1))
            
        #Using list comprehension to transform int items of the list in strings
        randomNumberList = "".join([str(letter) for letter in randomNumberList])

        return randomNumberList
    

    def generateGr(self, pseudorandomNumber: str, r: str) -> str:
        '''
        This method generates Gr
        In words, takes G(s) and only selects the bits of Gi(s) where in ri is 1
        '''
        grList = list()
        
        for i in range(len(r)):
            #For each r bit, check if this bit is equal to 1
            if (r[i] == "1"):
                #If this bit is equal to 1, add the G(s) bit to grList
                grList.append(pseudorandomNumber[i])

        #Transform the list in str
        gr = "".join(grList)

        return gr
    
    
    def generateC(self, b: str) -> list():
        '''
        This method concatenates 3 times b in order to create c with 3m, in words, q, and returns c
            -c = (b,b,b)
        '''

        c = list()

        for i in range(3):
            for bit in b:
                c.append(bit)

        #Using list comprehension to transform int items of the list in strings
        c = "".join([str(letter) for letter in c])

        print("C is : \n\t" + str(c))

        return c
    

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
    

    def generateG0(self, pseudorandomNumber: str, r: str) -> str: 
        '''
        This method generates G0
        In words, takes G(s) and only selects the bits of Gi(s) where in ri is 0
        '''
        g0List = list()
        
        for i in range(len(r)):
            #For each r bit, check if this bit is equal to 1
            if (r[i] == "0"):
                #If this bit is equal to 1, add the G(s) bit to grList
                g0List.append(pseudorandomNumber[i])

        g0 = "".join(g0List)

        return g0


    def generateR(self, q: int) -> str:
        '''
        This method generates a random vector r of length 2q
        '''
        r = list() #This is the vector of random numbers 

        #This bool is used to verify if our random vector has q bits equal to 1
        qBitsEqual1 = False

        while(not qBitsEqual1):
            #While our random vector has not q bits equal to 1

            for i in range(q*2): 
                randomNumber = secrets.randbelow(2)
                r.append(randomNumber)

            if (r.count(1) == q):
                qBitsEqual1 = True
            else:
                r = list()

        #Using list comprehension to transform int items of the list in strings
        r_str = "".join(str(r_bit) for r_bit in r)
        self.setLastR(r_str)

        return r_str

    def getLastR(self) -> str:
        '''
        Getter to r
        '''
        return self.r
    
    def setLastR(self, r: str):
        '''
        Setter to r
        '''
        self.r = r

    def binaryToDec(self, binaryNumber: bytearray) -> int:
        '''
        This method transforms a binaryNumber into integer
        '''
        return int(binaryNumber, 2)
    
    def compare(self, calculated, given) -> bool:
        '''
        This method compares the calculated value with the given one and returns True if both value are the same.
        '''
        if calculated == given:
            return True
        else:
            return False





if __name__ == '__main__':

    mqtt = Bob(MQTT_IP_ADDRESS,MQTT_USER, MQTT_PASSWORD, MQTT_PORT, MQTT_KEEPALIVE, USER_ID.decode('ascii'))

    #Create r
    r = mqtt.generateR(Q)

    #Send that r to Alice
    print("Sending r to Alice...")
    mqtt.publishMessage("MV37",r)

    #Set up the listener in order to receive the messages which Alice is going to send us
    mqtt.listenMessages()



