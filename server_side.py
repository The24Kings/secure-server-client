#!/usr/bin/python3

from socket import *
from typing import List
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import logging
import pickle
import threading

def encrypt_session_key(session_key: bytes, public_key: bytes) -> bytes:
    # Import public key
    public_key = RSA.importKey(public_key)

    # Encrypt session key with public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Return encrypted session key
    return enc_session_key

def decrypt_session_key(encrypted_session_key: bytes, private_key: bytes) -> bytes:
    # Import private key
    rsa_private_key = RSA.importKey(private_key)

    # Decrypt session key
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)
    
    # Return session key
    return session_key

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

def generate_RSA_keys() -> (bytes, bytes):
    # Generate RSA key
    key = RSA.generate(2048)

    # Export private key
    private_key = key.exportKey()

    # Export public key
    public_key = key.publickey().exportKey()

    # Return keys
    return public_key, private_key

def established_connection(
    connected_clients: dict, 
    client_socket: socket, 
    client_address: tuple, 
    public_key: RSA.RsaKey, 
    private_key: RSA.RsaKey
) -> None:
    while True:
        # Wait for client to send encrypted session key
        message = client_socket.recv(1024)
        logging.info(F"Message from client {client_address}: {message}")

        if message == b"CONNECT_SERVER":
            # Send encrypted session key
            logging.info(F"Sending public key to client {client_address}")
            client_socket.send(public_key)

        elif message == b"RECEIVE_SESSION_KEY":
            # Receive encrypted session key
            logging.info(F"Receiving encrypted session key from client {client_address}")
            message = client_socket.recv(1024)
            encrypted_session_key = message

            # Decrypt session key
            logging.info(F"Decrypting session key with private key")
            session_key = decrypt_session_key(encrypted_session_key, private_key)

            # Add client to connected clients
            logging.info(F"Adding client {client_address} to connected clients")
            connected_clients[client_address] = session_key

            break

        else:
            logging.critical(F"Refused conncetion to client {client_address}")
            client_socket.close()
            raise Exception("INVALID_HANDSHAKE")

    return

def on_new_client(
    server_socket: socket,
    client_socket: socket, 
    client_address: tuple, 
    connected_clients: dict
) -> None:
    error_count = 0

    # Receive messages from client
    while True:
        # Accept incoming message
        message = client_socket.recv(1024)

        # Deserialize message
        try:
            message = pickle.loads(message)
        except:
            logging.warning("No message received. Trying again...")
            error_count += 1

            if error_count == 5:
                logging.critical(F"Client {client_address} lost Connection.")
                break
            
            continue

        # Decrypt message with session key
        decrypted_message = decrypt_message(message, connected_clients[client_address])

        # Check if message is disconnect message
        if decrypted_message == b'DISCONNECT_SERVER':
            # Remove client from connected clients
            logging.warning(F"Client {client_address} disconnected.")

            del connected_clients[client_address]
            break

        # Stop the server and disconnect all clients
        if decrypted_message == b'KILL_SERVER':
            logging.warning(F"Server stopped by client {client_address}.")

            # TODO Use a queue to send a message to all clients to disconnect

            # Shutdown Main Thread
            server_socket.shutdown(SHUT_RDWR)
            server_socket.close()
            
        # Display message
        logging.info(F"Message from client {client_address}: {decrypted_message}")
        print(F"Message from client {client_address}: {decrypted_message}")
    
    # Close socket
    client_socket.close()

    return

"""    
    - Wait for client to send establish connection message
    - Send public key to client
    - Wait for client to send session key encrypted with public key
    - Decrypt session key with private key
    - Connection established :)
""" 

## TODO Make it so users can connect to other users that are conencted to the client

def main():
    path = "/home/rjziegler/fall2023/cs475/project2_encrypted_connection"
    logging.basicConfig(filename=path + "/server.log", level=logging.INFO)

    # Clear logging files
    open(path + "/server.log", "w").close()
    open(path + "/client.log", "w").close()
    
    # Log start
    logging.info("Starting server...")

    # Generate RSA keys
    logging.info("Generating RSA keys...")
    public_key, private_key = generate_RSA_keys()

    # Dictionary of connected clients -> {client_address: session_key}
    connected_clients = {}

    # Create Socket
    skt = socket(AF_INET, SOCK_STREAM)

    # Listen on every IP, transmit on 2424
    ip = "0.0.0.0"
    port = 2424
    address = (ip, port)

    logging.info(F"Binding socket to address: {ip} : {port}")

    # Bind socket to address
    skt.bind(address)

    # Refuse connections after 5 tries
    skt.listen(15)

    # Accept connection -> (conn, addr)
    while True:
        try:
            client_socket, client_address = skt.accept()
        except KeyboardInterrupt:
            logging.critical("Server stopped by user.")
            break

        logging.info(F"Client {client_address} connected!")

        # Check if client is not already connected
        if client_address not in connected_clients:
            try:
                established_connection(connected_clients, client_socket, client_address, public_key, private_key)
            except:
                logging.critical("Unable to establish connection to client.")
                continue

        # Create thread for client
        thread = threading.Thread(target=on_new_client, args=(skt, client_socket, client_address, connected_clients))
        thread.setDaemon(True)
        logging.info(F"Starting thread for client {client_address} : {thread.getName()}")

        thread.start()

    # Close underlying allocations
    skt.close()
    logging.shutdown()
    exit()

if __name__ == "__main__":
    main()
