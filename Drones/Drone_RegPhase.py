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

        temp_ID_drone = recv_data_with_length(s)
        pseudo_ID_drone = recv_data_with_length(s)
        polynomial_share = recv_data_with_length(s)
        cert_drone = recv_data_with_length(s)
        ID_CR = recv_data_with_length(s)
        private_value = recv_data_with_length(s)
        public_key_text = recv_data_with_length(s)
        
        s.close()

    pseudo_ID_drone = int.from_bytes(pseudo_ID_drone, byteorder='big')
    polynomial_share = pickle.loads(polynomial_share)
    cert_drone = cert_drone.decode()
    ID_CR = ID_CR.decode()

    # Generating private key of the drone from the private value received from the CR
    private_key = ec.derive_private_key(int.from_bytes(private_value, byteorder='big'), ec.SECP256K1())

    with open("Drone_credentials.txt", "w+") as f:
        f.write("PID:\t" + str(pseudo_ID_drone) + "\n")
        f.write("Polynomial share:\t" + str(polynomial_share) + "\n")
        f.write("Cert:\t" + str(cert_drone) + "\n")
        f.write("ID_CR:\t" + str(ID_CR) + "\n")
    

    # Serializing the private key of the drone to a file
    serialized_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'testpassword')
    )



    with open('../Public/Drone_public.pem', 'wb') as f:
        f.write(public_key_text)

    with open('Drone_public.pem', 'wb') as f:
        f.write(public_key_text)

    with open('Drone_private.pem', 'wb') as f:
        f.write(serialized_private)



if __name__ == '__main__':
    main()