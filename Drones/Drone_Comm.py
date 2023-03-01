import sys
import socket
from struct import pack, unpack
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


'''
Utility function to send byte stream data with length to the socket. 
Sends the length first by packing it into a 4 byte integer.
'''
def send_data_with_length(data: bytes, socket: socket.socket):
    length = len(data)
    socket.sendall(pack('>I', length))
    socket.sendall(data)

'''
Receive bytes data from the TCP stream. Data is accompanied
by its length first.
'''
def recv_data_with_length(s: socket.socket) -> bytes:
    data_len = s.recv(4)
    data_len = unpack('>I', data_len)[0]
    data = s.recv(data_len)
    return data


'''
Function to generate a derived key from the private key of drone1 and the public key of drone2
using ECDH key exchange.
'''
def generate_derived_key(drone1: int, drone2: int) -> bytes:
    # Prepare for sharing key
    with open(f"Credentials/Drone{drone1}_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    with open(f"../Public/Drone{drone2}_public.pem", "rb") as key_file:
        peer_public_key = serialization.load_pem_public_key(
            key_file.read(),
        )

    # Generate a shared key
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive a symmetric encryption key from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
    ).derive(shared_key)

    return derived_key


'''
Function to handle requests from the drones and take care of the communication.
Receives the drone number from the drone and retrieves its socket from the socket_list.
'''
def handle_requests(conn1: socket.socket, drone_number: int, socket_list: dict):

    # Does Drone {i} want to connect to another drone?
    drone_connect = recv_data_with_length(conn1).decode()

    if drone_connect == "N":
        return

    while True:
        # Only comes here if drone {i} wants to connnect to someone 
        # Which drone does Drone {i} want to connect to?
        drone_request = recv_data_with_length(conn1).decode()

        # Sending a connection request to the drone
        send_data_with_length(f"Drone {drone_number} wants to connect.".encode(), socket_list[int(drone_request)])

        # Receiving response from the drone
        response = recv_data_with_length(socket_list[int(drone_request)]).decode()

        # Sending response to the drone {i}
        if response == "N":
            send_data_with_length("Connection request declined.".encode(), conn1)
            continue

        else:
            send_data_with_length("Connection request accepted.".encode(), conn1)

            while True:
                data = recv_data_with_length(conn1)

                if data == b"exit":
                    send_data_with_length(data, socket_list[int(drone_request)])
                    break
                nonce = recv_data_with_length(conn1)

                send_data_with_length(data, socket_list[int(drone_request)])
                send_data_with_length(nonce, socket_list[int(drone_request)])

                data = recv_data_with_length(socket_list[int(drone_request)])
                if data == b"exit":
                    send_data_with_length(data, conn1)
                    break

                nonce = recv_data_with_length(socket_list[int(drone_request)])

                send_data_with_length(data, conn1)
                send_data_with_length(nonce, conn1)

            continue


'''
Function to handle the transmission between the drones after they have been connected.
chacha is the ChaCha20Poly1305 object used for encryption and decryption.
'''
def transmission(drone_connect: str, s: socket.socket, chacha: ChaCha20Poly1305):
    while True:
        print("Me:", end = ' ')
        data = input()

        if data == "exit":
            send_data_with_length(data.encode(), s)
            break

        nonce = os.urandom(12)
        data1 = chacha.encrypt(nonce, data.encode(), None)

        send_data_with_length(data1, s)
        send_data_with_length(nonce, s)

        
        
        response = recv_data_with_length(s)
        if response == b"exit":
            break
        nonce = recv_data_with_length(s)

        response = chacha.decrypt(nonce, response, None).decode()
        print(f"Drone {drone_connect}: {response}")




def main():

    if(len(sys.argv) != 3):
        print("Usage: python3 Drone_Comm.py <s/c> <Drone number(Cannot be 1 if not s)>")
        return
    
    if(sys.argv[1] != "s" and sys.argv[1] != "c"):
        print("Invalid argument: <s/c> is required")
        return
    
    curr_drone = int(sys.argv[2])

    if (sys.argv[1] == "c") and (curr_drone == 1):
        print("Invalid argument: Drone number cannot be 1")
        return
    
    '''
    Fixing drone1 as master drone and hence the server which coordinates
    transmission between other drones.
    '''
    if(sys.argv[1] == "s"):
        
        # Start server
        print("Starting server...")

        num_of_drones = 5

        # to store the address of each drone connection
        address = dict()

        # To store the sockets of each drone connection
        socket_list = dict()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('localhost', 9008))
        s.listen(num_of_drones - 1)

        thread_list = []

        for _ in range(num_of_drones - 1):
            conn, addr = s.accept()

            # Storing address of each connected drone
            drone_number = int(recv_data_with_length(conn).decode())
            address[drone_number] = addr
            socket_list[drone_number] = conn

            # Create a thread to handle this connection
            t1 = threading.Thread(target=handle_requests, args=(conn, drone_number, socket_list,))
            thread_list.append(t1)

        [t.start() for t in thread_list]
        [t.join()  for t in thread_list]


            

            
    else:
        # Start client
        drone_number = int(sys.argv[2])

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 9008))
            send_data_with_length(str(drone_number).encode(), s)

            # Ask if drone wants to connect to another drone
            print("Do you want to connect to another drone? (Y/N)")
            drone_connect = input()
            send_data_with_length(drone_connect.encode(), s)

            if drone_connect == "Y":
                while True:
                    print("Enter the drone number you want to connect to")

                    # Sending a connection request to the server
                    drone_connect = input()
                    drone_connect = drone_connect.encode()
                    send_data_with_length(drone_connect, s)

                    # Receiving response from the server
                    response = recv_data_with_length(s).decode()
                    # print(response)

                    if response == "Connection request declined.":
                        print(response)

                    else:
                        print(response)

                        derived_key = generate_derived_key(drone_number, int(drone_connect.decode()))
                        chacha = ChaCha20Poly1305(derived_key)

                        transmission(drone_connect.decode(), s, chacha)
                        continue
                        

            else:
                while True:
                    print("Waiting for connection requests...")

                    # Drone {i} wants to connect.
                    response = recv_data_with_length(s)
                    print(response.decode())

                    responder_name = response.decode()[:7]

                    responder_num = responder_name[-1]
                    print("Enter Y/N to accept/decline the connection request.")
                    choice = input()

                    send_data_with_length(choice.encode(), s)

                    if(choice == "N"):
                        print("Connection request declined.")
                    
                    else:
                        print("Connection request accepted.")

                        derived_key = generate_derived_key(drone_number, int(responder_num))
                        chacha = ChaCha20Poly1305(derived_key)


                        # initial response
                        response = recv_data_with_length(s)
                        if response == b"exit":
                            break
                        nonce = recv_data_with_length(s)

                        response = chacha.decrypt(nonce, response, None).decode()

                        print(f"{responder_name}: {response}")
                        transmission(responder_num, s, chacha)
                

if __name__ == "__main__":
    main()