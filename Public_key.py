import gmpy2
from gmpy_prime import *
from gmpy2 import powmod, is_prime, gcd

class PublicKey:
    '''
    Class to be used for Public Key encryption entities
    Member function :
        key_gen(file_name)
        encrypt(message)
        add_homo(c1,c2)
    '''
    
    def __init__(self):
        pass

    def key_gen(self, file_name = "public_key.txt"):
        '''
        Arguments :
            file_name - name of the file containing public keys (set as 'public_key.txt' by default)
        
        Action :
            Opens file file_name and reads public key (n.g) through the lines
        '''
        f = open(file_name,'r')
        lines = f.readlines()
        self.n = gmpy2.mpz(lines[0].split()[0])
        self.g = gmpy2.mpz(lines[1].split()[0])
        self.bits=  gmpy2.mpz(gmpy2.rint_round(gmpy2.log2(self.n)))
        self.n2 = self.n * self.n

    def encrypt(self, m):
        '''
        Arguments :
            m - plain text message to be encrypted
        
        Return Value :
            cipher text formed by encyption of plain text m
        
        Action :
            Performs Paillier Encryption on plain text m using the public key pair
        '''
        assert(m <= self.n)
        r=gmpy2.mpz_urandomb(rand, self.bits)

        while gcd(r,self.n) > 1 or r >= self.n or r < 0:
            r=gmpy2.mpz_urandomb(rand, self.bits)
            
        cipher = (powmod(self.g, m, self.n2)) * (powmod(r, self.n, self.n2) ) % self.n2
        return cipher

    def add_homo(self, c1, c2):
        '''        
        Arguments :
            c1 , c2 - set of ciphertexts to be added
        
        Action :
            Performs Homomorphic Addition of c1 and c2 by multiplying them

        Return Value :
            ciphertext of the sum of plain texts corresponding to c1 and c2
        '''
        return (c1 * c2) % self.n**2

if __name__ == '__main__':
    Pu = PublicKey()
    Pu.key_gen()
    m = 12345
    c = Pu.encrypt(m)
    print(c)