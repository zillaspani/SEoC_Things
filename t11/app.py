import datetime
import json
import logging
import os
import random
import socket
from threading import Lock
import threading
import time

class Thing:

    rec_lock=Lock()
    lock=Lock()
    my_auth={}
    seggested_auth={}
    tried=[]
    my_things={}
    current_comm=[]
    TIMEOUT=10
    MAX_TRIES=3

    def __init__(self):
        self.load_init_config()
        logging.basicConfig(
        level=logging.INFO,
        filename=f"data/log/{self.hostname}_log.log",
        format='%(asctime)s,%(msecs)d %(levelname)s %(message)s',
        datefmt='%H:%M:%S')

    def load_init_config(self):
        try:
            with open('data/config/config.json', 'r') as json_file:
                data = json.load(json_file)
            self.hostname=data['HOSTNAME']
            self.ip=data["IP"]
            self.port=data["UDP_PORT"]
            self.security_req=data['SEC_REQ']
            self.seggested_auth=data['SUGGESTED_AUTH']
            self.my_things=self.load_things(data['THINGS'])
            self.thing_port=data['UDP_PORT_THING']
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.ip, self.thing_port))
        except FileNotFoundError:
            logging.error("Config file not found.")
        except json.JSONDecodeError:
            logging.error("Error decoding JSON data. Check if the JSON config file is valid.")
        except Exception as e:
            logging.error("An unexpected error occurred:", e)

    def load_things(self,things):
        try:
            tmp=things
            for thing in things:
                tmp[thing]['SESSION_KEY']="no key"
                tmp[thing]['COMM']=True
            return tmp
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during load_things")

    def decode_message(self,data,address):
        '''
        Give message and andress, it will decode the encrypt message in a plaintext message in json format.
        For now, it only trasform the stream in json.
        '''
        try:
            plain=json.loads(data)
            return plain
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during decode_message")

    def get_message_type(self, type):
        if type == 0:
            return "REGISTER_TO_AUTH"
        elif type == 1:
            return "REGISTER_RESPONSE"
        elif type == 2:
            return "CONNECT_TO_AUTH"
        elif type == 3:
            return "AUTH_HELLO"
        elif type == 4:
            return "SESSION_KEY_REQUEST"
        elif type == 5:
            return "SESSION_KEY_RESPONSE"
        elif type == 6:
            return "AUTH_SESSION_KEYS"
        elif type == 7:
            return "TRIGGER_THING"
        elif type == 8:
            return "AUTH_UPDATE"
        elif type == 9:
            return "UPDATE_REQUEST"
        elif type == 10:
            return "UPDATE_KEYS"
        elif type == 11:
            return "START"
        else:
            return "Unknown message type"

    def send(self,receiver_ip,receiver_port,message):
        try:
            UDP_IP = receiver_ip
            UDP_PORT = receiver_port
            MESSAGE = message
            MESSAGE_BYTE=json.dumps(MESSAGE).encode("UTF-8")
            sock = socket.socket(socket.AF_INET, 
                                socket.SOCK_DGRAM) 
            sock.sendto(MESSAGE_BYTE, (UDP_IP, UDP_PORT))
            logging.info(f"Sent {self.get_message_type(message['MESSAGE_TYPE'])}:\n{message}\nto {receiver_ip}:{receiver_port}")
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during send, with {receiver_ip}:{receiver_port}")

    def receive(self,expected):
        try:
            logging.debug(f"Try to receive message with MESSAGE_TYPE {expected}")    
            UDP_IP = self.ip
            UDP_PORT = self.port
            sock = socket.socket(socket.AF_INET,
                                socket.SOCK_DGRAM)
            sock.bind((UDP_IP, UDP_PORT))
            sock.settimeout(self.TIMEOUT)
            data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
            plain_message = self.decode_message(data, addr)
            if plain_message['MESSAGE_TYPE']==expected:
                logging.info(f"Received {self.get_message_type(plain_message['MESSAGE_TYPE'])}\nmessage: {plain_message} from {plain_message['ADDRESS']}:{plain_message['PORT']}")
                return plain_message,addr
            else:
                raise TimeoutError
        except TimeoutError as timeout:
            logging.info(f"Timeout for message type: {expected}")
            return "TIMEOUT",expected
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during receive")

    def get_auth_to_contact_old(self):
        try:
            auth_list=list(self.seggested_auth)
            auth_address_port=self.seggested_auth.pop(auth_list[0])
            return auth_list[0],auth_address_port
        except IndexError as ex:
            logging.info("List of suggested auth empty, done")
            logging.debug("EXIT")
            exit(-1)
    
    def get_auth_to_contact(self):
        try:
            for auth in self.seggested_auth:
                if auth not in self.tried:
                    self.tried.append(auth)
                    return auth, self.seggested_auth.pop(auth)
            logging.info("List of suggested auth empty, done")
            logging.debug("EXIT")
            exit(-1)
        except Exception as ex:
            logging.info("List of suggested auth empty, done")
            logging.debug("EXIT")
            exit(-1)

    def register_response(self,message):
        try:
            if message['ACCEPTED']==1:
                self.my_auth={
                    "HOSTNAME": message['AUTH_ID'],
                    "ADDRESS": message['ADDRESS'],
                    "PORT": message['PORT'],
                    "SESSION_KEY" : message['SESSION_KEY']
                }
                logging.info(f"My auth setted\n{self.my_auth}")
                self.seggested_auth=message['SUGGESTED_AUTH']
                self.send_logger("REGISTERED")
            else:
                #self.seggested_auth=message['SUGGESTED_AUTH']
                self.register_to_auth()
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during register_response")
        
    def handle_register_to_auth_failed(self,message):
        '''
        When an auth does not respond for 3 attempts or the next registration attempts following receipt of SUGGESTED_AUTH are again declined.
        In general, connection attempts continue until the list of SUGGESTED_AUTH is exhausted.
        '''
        if self.seggested_auth != {}:
            logging.info("Try to connect with another auth")
            self.register_to_auth()
        else:
            logging.info("List of suggested auth is empty, I will die alone")
            exit(-1)

    def register_to_auth(self):
        try:
            message={
                "MESSAGE_TYPE": 0,
                "THING_ID": self.hostname,
                "ADDRESS":self.ip,
                "PORT":self.port,
                "SEC_REQ": self.security_req,
                "THING_SIGNATURE": "E[(THING_ID | ADDRESS | PORT | SEC_REQ),thing private key]"
                }
            auth_hostname,auth_addr=self.get_auth_to_contact()
            ATTEMPT=0
            while ATTEMPT < self.MAX_TRIES:
                self.rec_lock.acquire()
                self.send(auth_addr['ADDRESS'],auth_addr['PORT'],message)
                response, address= self.receive(1)
                self.rec_lock.release()
                if response != "TIMEOUT":
                    logging.debug(f"{response}\nfrom: {address}")
                    self.register_response(response)
                    return
                else:
                    logging.debug(f"Register_to_auth {auth_hostname}: Attempt {ATTEMPT+1}/{self.MAX_TRIES}")
                    ATTEMPT+=1

            self.handle_register_to_auth_failed(response)
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error register_to_auth routine")

    def handle_connect_to_auth_failed(self):
        logging.debug("My auth is not respondig, i will handle this problem")
        self.my_auth={}
        return
        
    def connect_to_auth(self):
        try:
            message={
                "MESSAGE_TYPE": 2,
                "THING_ID": self.hostname,
                "ADDRESS": self.ip,
                "PORT": self.port
            }   
            
            ATTEMPT=0
            while ATTEMPT < self.MAX_TRIES:
                self.rec_lock.acquire()
                self.send(self.my_auth['ADDRESS'],self.my_auth['PORT'],message)
                response, address= self.receive(3)
                self.rec_lock.release()
                if response != "TIMEOUT":
                    self.send_logger("CONNECT")
                    logging.debug(f"{response}\nAUTH_HELLO from: {address}\nResponse:\n{response}")
                    return response['A_NONCE']
                    #the next call in routine will be SESSION_KEY_REQUEST
                else:
                    logging.debug(f"connect_to_auth {self.my_auth['HOSTNAME']}: Attempt {ATTEMPT+1}/{self.MAX_TRIES}")
                    ATTEMPT+=1

            self.handle_connect_to_auth_failed()
            return
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error connect_to_auth routine")

    def get_thing_to_ask(self):
        try:
            l=[]
            for thing in self.my_things:
                if self.my_things[thing]['COMM']==True:
                    l.append(thing)
            return l
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_thing_to_ask handling")

    def session_key_request(self,nonce):
        try:
            thing_to_require=self.get_thing_to_ask()
            if thing_to_require==[]:
                return 
            message={
                "MESSAGE_TYPE": 4,
                "THING_ID": self.hostname,
                "ADDRESS": self.ip,
                "PORT":self.port,
                "A_NONCE": nonce,
                "T_NONCE": str(os.urandom(2)),
                "WHO": thing_to_require
            }
            ATTEMPT=0
            while ATTEMPT < self.MAX_TRIES:
                self.rec_lock.acquire()
                self.send(self.my_auth['ADDRESS'],self.my_auth['PORT'],message)
                response, address= self.receive(5)
                self.rec_lock.release()
                if response != "TIMEOUT":
                    logging.debug(f"{response}\nSESSION_KEY_RESPONSE from: {address[0]}\nResponse:\n{response}")
                    self.update_things(response['SESSION_KEY'])
                    self.trigger_things()
                    return
                else:
                    logging.debug(f"session_key_request to {self.my_auth['HOSTNAME']}: Attempt {ATTEMPT+1}/{self.MAX_TRIES} failed")
                    ATTEMPT+=1

            self.handle_connect_to_auth_failed() #same behave when the auth doesn't response
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during session_key_request")

    def get_thing_address(self,thing):
        try:
            logging.debug(f"get_thing_address {self.my_things[thing]}")
            return self.my_things[thing]
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during get_thing_address for {thing}")

    def trigger_things(self):
        logging.info("Trigger things")
        try:
            message={
                "MESSAGE_TYPE":7,
                "THING_ID":self.hostname,
                "ADDRESS": self.ip,
                "PORT":self.thing_port,
                "T_NONCE": str(os.urandom(2))
            }
            for thing in self.my_things:
                if self.my_things[thing]['COMM']==True and self.my_things[thing]['SESSION_KEY']!="no key":
                    address=self.get_thing_address(thing)
                    self.send(address['ADDRESS'],address['PORT'],message)
            return             
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during trigger_things")

    def update_things(self,session_key):
        try:
            for thing in session_key:
                self.my_things[thing]['SESSION_KEY']=session_key[thing]
            logging.info(f"List of things update:\n{self.my_things}")

        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during update_things")

    def add_thing(self,message):
        try:
            session_key="no key"
            comm=False
            new_thing={
                "ADDRESS": message['ADDRESS'],
                "PORT": message['PORT'],
                "SESSION_KEY": session_key,
                "COMM":comm
            }
            #self.lock.acquire()
            self.my_things[message['THING_ID']]=new_thing
            #self.lock.release()
            logging.debug(f"Thing aggiunta:\n{new_thing}")
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during add_thing handling, with {message['ADDRESS']}:{message['PORT']}")

    def update_request(self,message):
        try:
            self.add_thing(message)
            message={
                "MESSAGE_TYPE": 9,
                "THING_ID": self.hostname,
                "ADDRESS": self.ip,
                "PORT": self.port,
                "T_NONCE": str(os.urandom(2))
            }

            ATTEMPT=0
            while ATTEMPT < self.MAX_TRIES:
                self.rec_lock.acquire()
                self.send(self.my_auth['ADDRESS'],self.my_auth['PORT'],message)
                response, address= self.receive(10)
                self.rec_lock.release()
                if response != "TIMEOUT":
                    self.update_things(response['SESSION_KEYS'])
                    self.start()
                    return
                else:
                    logging.debug(f"update_request to {self.my_auth['HOSTNAME']}: Attempt {ATTEMPT+1}/{self.MAX_TRIES} failed")
                    ATTEMPT+=1

            self.handle_connect_to_auth_failed() #same behave when the auth doesn't response
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during update_request")

    def start(self):
        logging.info("Start communication with things")
        try:
            message={
                "MESSAGE_TYPE":11,
                "THING_ID":self.hostname,
                "ADDRESS": self.ip,
                "PORT":self.thing_port,
                "T_NONCE": str(os.urandom(2))
            }
            for thing in self.my_things:
                logging.info(f"iter on {thing}")
                logging.info(f"{self.my_things[thing]}")
                if self.my_things[thing]['COMM']==False and self.my_things[thing]['SESSION_KEY']!="no key":
                    address=self.get_thing_address(thing)
                    self.send(address['ADDRESS'],address['PORT'],message)
            return             
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during start")

    def routine(self):
        '''
        Lifetime of things is divided in several phases,
        As first we have the register phase were a thing want to connect to an Auth. 
        '''
        try:
            count=0
            while True:
                time.sleep(random.randint(5,16))
                #Start: Register phase
                #Restart: When handle_connect_to_auth_failed set my_auth as empty cause the auth didn't response to a message. 
                if self.my_auth == {}:
                    count=0
                    logging.info("No Auth found try to connect with new one")
                    self.register_to_auth()
                #End: When my_auth in not empty 
                else:
                    logging.info(f"Auth found try to connect with {self.my_auth['HOSTNAME']} it: {count}")
                    nonce=self.connect_to_auth()
                    count+=1
                    if count==7 and self.my_things != {}: #Just to simulate the need of commutication after some time. When the condition is true it try to obtain the key for communication and communicate
                        self.session_key_request(nonce)
                    else:
                        logging.info("I JUST WANT TO CHECK MY AUTH")
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during routine")

    def response_start(self,message):
        try:

            record=f"TALK {self.hostname} ---> {message['THING_ID']}\n"
            MESSAGE_BYTE=json.dumps(record).encode("UTF-8")
            sock = socket.socket(socket.AF_INET, 
                                socket.SOCK_DGRAM) 
            sock.sendto(MESSAGE_BYTE, (self.ip, 2201))
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during response_start handling")

    def handle_client(self, data, address):
        plain_message = self.decode_message(data, address)
        logging.info(f"Received {self.get_message_type(plain_message['MESSAGE_TYPE'])}\nmessage: {plain_message} from {plain_message['ADDRESS']}:{plain_message['PORT']}")
        if plain_message['MESSAGE_TYPE'] == 7:
            self.update_request(plain_message)
        elif plain_message['MESSAGE_TYPE'] == 11:
            self.response_start(plain_message)
            logging.info(f"START message from thing {plain_message['THING_ID']}")
        else:
            logging.error("Message type was not recognized")

    def listenT(self):
        while True:
            data, address = self.socket.recvfrom(1024)
            self.handle_client(data,address)
            
    def start_listening(self):
        logging.debug(f"{self.hostname} Start Listening on {self.ip}:{self.port}")
        listening_thread = threading.Thread(target=self.listenT, daemon= True)
        listening_thread.start()

    def send_logger(self,message_code):
        try:
            record=f"{message_code} {self.hostname} ---> {self.my_auth['HOSTNAME']}\n"
            if message_code == "CONNECT":
                MESSAGE_BYTE=json.dumps(record).encode("UTF-8")
                sock = socket.socket(socket.AF_INET, 
                                    socket.SOCK_DGRAM) 
                sock.sendto(MESSAGE_BYTE, (self.ip, 2200))
            else:
                MESSAGE_BYTE=json.dumps(record).encode("UTF-8")
                sock = socket.socket(socket.AF_INET, 
                                    socket.SOCK_DGRAM) 
                sock.sendto(MESSAGE_BYTE, (self.ip,2202))
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during send_logger handling")

    def template(self,message,address):
        try:
            pass
        except Exception as ex:
            logging.error(ex)
            logging.error(f"Error during template handling")

if __name__ == "__main__":


    thing = Thing()
    thing.start_listening()
    thing.routine()

