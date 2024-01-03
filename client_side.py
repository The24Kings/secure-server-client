#!/usr/bin/python3

from socket import *
from typing import List
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import logging
import os
import pickle

def encrypt_session_key(session_key: bytes, public_key: bytes) -> bytes:
    # Import public key
    public_key = RSA.importKey(public_key)

    # Encrypt session key with public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Return encrypted session key
    return enc_session_key

def encrypt_message(message: bytes, session_key: bytes) -> List:
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    
    return [cipher_aes.nonce, tag, ciphertext]

def decrypt_message(encrypted_data: List, session_key: bytes) -> str:
    nonce = encrypted_data[0]
    tag = encrypted_data[1]
    ciphertext = encrypted_data[2]

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    return message

def main() -> None:
    path = "/home/rjziegler/fall2023/cs475/project2_encrypted_connection"
    logging.basicConfig(filename=path + "/client.log", level=logging.INFO)

    # Create Socket
    skt = socket(AF_INET, SOCK_STREAM)

    try:
        # Listen on every IP, transmit on 2424
        skt.connect(("isoptera.lcsc.edu", 2424))
    except(ConnectionRefusedError):
        logging.info("Connection refused.")
        return

    skt.send(b"CONNECT_SERVER")

    # Wait for server to send public key
    logging.info("Receiving public key...")
    public_key = skt.recv(2048)
    logging.info("Public key received!")

    # Generate session key
    session_key = get_random_bytes(16)

    # Encrypt session key with public key
    encrypted_session_key = encrypt_session_key(session_key, public_key)

    #Send b'RECEIVE_SESSION_KEY' message to server
    logging.info("Sending RECEIVE_SESSION_KEY message...")
    skt.send(b"RECEIVE_SESSION_KEY")

    # Send encrypted session key to server
    logging.info("Sending encrypted session key...")
    skt.send(encrypted_session_key)

    # Prompt user for message
    while True:
        message = input("Enter message: ")

        logging.info("Sending message: " + message)

        # Exit if user enters "exit"
        if message == "exit":
            message = "DISCONNECT_SERVER"

        if message == "stop":
            message = "KILL_SERVER"

        # Encrypt message
        encrypted_message = encrypt_message(message.encode("utf-8"), session_key)

        # Serialize encrypted message
        data = pickle.dumps(encrypted_message)

        # Send encrypted message
        try:
            skt.send(data)
        except BrokenPipeError:
            print("Message could not be sent.")
            print("Server disconnected.")
            logging.critical("Server disconnected.")
            break

        # Exit if user enters "exit"
        if message == "DISCONNECT_SERVER":
            logging.info("Disconnecting from server...")
            break

        if message == "KILL_SERVER":
            logging.warning("Killing server...")
            break

    # Close socket
    logging.warning("Closing socket...")
    skt.close()
    logging.shutdown()

if __name__ == "__main__":
    main()