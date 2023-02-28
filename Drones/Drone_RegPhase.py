import socket
import pickle
from struct import unpack
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

'''
Receive bytes data from the TCP stream. Data is accompanied
by its length first.
'''
def recv_data_with_length(s: socket.socket) -> bytes:
    data_len = s.recv(4)
    data_len = unpack('>I', data_len)[0]
    data = s.recv(data_len)
    return data

def main():
    # Connect to the CR to receive credentials
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 5050))

        index_drone = recv_data_with_length(s)
        temp_ID_drone = recv_data_with_length(s)
        pseudo_ID_drone = recv_data_with_length(s)
        polynomial_share = recv_data_with_length(s)
        cert_drone = recv_data_with_length(s)
        ID_CR = recv_data_with_length(s)
        private_value = recv_data_with_length(s)
        public_key_text = recv_data_with_length(s)
        
        s.close()

    index_drone = int(index_drone.decode('utf-8'))
    temp_ID_drone = int(temp_ID_drone.decode('utf-8'))
    pseudo_ID_drone = int.from_bytes(pseudo_ID_drone, byteorder='big')
    polynomial_share = pickle.loads(polynomial_share)
    cert_drone = cert_drone.decode()
    ID_CR = ID_CR.decode()
    private_value = int(private_value.decode())

    # Generating private key of the drone from the private value received from the CR
    private_key = ec.derive_private_key(private_value, ec.SECP256K1())

    with open(f"Credentials/Drone{index_drone}_credentials.txt", "w+") as f:
        f.write(f"TID:\t{str(temp_ID_drone)}\n")
        f.write(f"PID:\t{str(pseudo_ID_drone)}\n")
        f.write(f"Polynomial share:\t{str(polynomial_share)}\n")
        f.write(f"Cert:\t{str(cert_drone)}\n")
        f.write(f"ID_CR:\t{str(ID_CR)}\n")
    

    # Serializing the private key of the drone to a file
    serialized_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )



    with open(f'../Public/Drone{index_drone}_public.pem', 'wb') as f:
        f.write(public_key_text)

    with open(f'Credentials/Drone{index_drone}_public.pem', 'wb') as f:
        f.write(public_key_text)

    with open(f'Credentials/Drone{index_drone}_private.pem', 'wb') as f:
        f.write(serialized_private)



if __name__ == '__main__':
    main()