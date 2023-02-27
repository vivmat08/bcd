import socket
import pickle
from struct import pack, unpack
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
        s.connect(('localhost', 5051))

        pseudo_ID_GSS = recv_data_with_length(s)
        polynomial_share = recv_data_with_length(s)
        cert_GSS = recv_data_with_length(s)
        ID_CR = recv_data_with_length(s)
        
        s.close()

    pseudo_ID_GSS = int.from_bytes(pseudo_ID_GSS, byteorder='big')
    polynomial_share = pickle.loads(polynomial_share)
    cert_GSS = cert_GSS.decode()
    ID_CR = ID_CR.decode()

    with open("GSS_credentials.txt", "w+") as f:
        f.write("PID_GSS:\t" + str(pseudo_ID_GSS) + "\n")
        f.write("Polynomial share:\t" + str(polynomial_share) + "\n")
        f.write("Cert_GSS:\t" + str(cert_GSS) + "\n")
        f.write("ID_CR:\t" + str(ID_CR) + "\n")
    
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()

    serialized_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
    )

    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('../Public/GSS_public.pem', 'wb') as f:
        f.write(serialized_public)

    with open('GSS_public.pem', 'wb') as f:
        f.write(serialized_public)

    with open('GSS_private.pem', 'wb') as f:
        f.write(serialized_private)



if __name__ == '__main__':
    main()