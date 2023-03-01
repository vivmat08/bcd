# Private blockchain-envisioned drones-assisted authentication scheme

This is an implementation of the [paper](https://www.sciencedirect.com/science/article/pii/S0920548921000623) titled "Private blockchain-envisioned drones-assisted authentication scheme in IoT-enabled agricultural environment"
using python3 and the cryptography library.

Please make sure you have all the required libraries pre-installed and that each code is run from it's own directory.

The steps to use this code are as follows:

1. First run the CR_SysInitPhase.py to generate the keys of CR and all other required parameters.
2. Set the number of drones in the CR_RegPhase.py file. Then, run the CR_RegPhase.py and the GSS_RegPhase.py, followed by as many instances of the Drone_RegPhase.py as there are nubmer of drones.
3. Finally, run the Drones_Comm.py file to inititate secured communication between drones.
The way to run the Drones_Comm.py file is 
`python3 Drones_Comm.py <s/c for server/client> <Drone number(cannot be 1 if client)>`

NOTE:
1. All the data supposed to be made public is written/stored in the Public directory. 
2. The drones use Elliptic Curve Diffie Hellman (ECDH) to generate a key for the symmetric cipher ulitmately used to encrypt all communications, ChaCha20Poly1305.
3. The drone 1 is assumed to be the master drone through which all other drones communicate with each other, while the drone itself cannot read their communication.
