# Paillier-Encryption-in-gmpy2
There are two classes implemented:
1. PublicKey : used by the general public key encryption entity , to encrypt plaintext. Contains member function for homomorphic addition. The Keys are extracted from a txt file (provided in the arguments, set as 'public_key.txt' by default)
2. PrivateKey : A Child class derived from PublicKey. This class is used by the private key entity , to decrypt the messages. Contains member function for verifying homomorphic addition. The pair of Public Keys on generation are stored in a txt  file (provided in the arguments, set as 'public_key.txt by default'"
