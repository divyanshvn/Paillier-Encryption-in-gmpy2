import gmpy2
from Public_key import PublicKey
from gmpy_prime import *
from gmpy2 import powmod, is_prime, invert

class PrivateKey(PublicKey):
    '''
    Inherited from PublicKey. 
    KeyGen leads to storing the public keys in txt file, to be shared with the PublicKey entities
    '''
    def __init__(self):
        self.L = lambda x, y: (x-1)//y
        return

    def key_gen(self, num_bits, file_name = "public_key.txt", simple = False):
        self.p = generate_prime(num_bits//2)
        self.q = generate_prime(num_bits//2)

        assert(is_prime(self.p))
        while self.p == self.q:
            self.q = generate_prime(num_bits)

        assert(is_prime(self.q))

        self.n = self.p * self.q
        self.bits=  gmpy2.mpz(gmpy2.rint_round(gmpy2.log2(self.n)))
        self.n2 = self.n * self.n
        self.l = gmpy2.lcm(self.p-1, self.q-1)

        self.g = get_ranged_random_integer(0,self.n**2)
        t = self.L(powmod(self.g, self.l, self.n**2), self.n)

        while not (gmpy2.gcd(t,self.n) == 1):
            self.g = get_ranged_random_integer(0,self.n**2)
            t = self.L(powmod(self.g, self.l, self.n**2), self.n)
        self.mu = gmpy2.invert(t, self.n)

        if simple:
            self.g = self.n + 1         # simple implementation
            phi = ((self.p - 1) * (self.q - 1)) % self.n
            self.mu = invert(phi,self.n)
            self.l = phi

        with open(file_name,'w') as f:
            f.write(str(self.n))
            f.write('\n')
            f.write(str(self.g))

        return

    def decrypt(self, c):
        '''
        Decrypts ciphertext into plaintext
        '''
        t1 = powmod(c, self.l, self.n2)
        m1 = self.L(t1,self.n)
        m = (m1 * self.mu) % self.n
        return m

    def is_homomorphic(self, c_sum, c1, c2):
        '''
        Checks if the claim : c_sum = E(D(c1)+D(c2)) is true
        '''
        m1 = self.decrypt(c1)
        m2 = self.decrypt(c2)

        m_sum = self.decrypt(c_sum)
        return ((m1+m2)%self.n == m_sum)

if __name__ == '__main__':
    P = PrivateKey()
    P.key_gen(1024)
    c1 = P.encrypt(123234324252352324324)
    # print(c)
    c2 = P.encrypt(23412412312424141414314343242423423243242958209583209538250932850923852309852309583209583209582309583209583209583209853209583205983095832095832095832098532095832095823095823095828039285320958320958032985093285029358325732785683275632465238469183740918410479386587236578236598320750923)
    c3 = (c1 * c2) % (P.n ** 2)
    c_sum = P.add_homo(c1,c2)
    m1 = P.decrypt(c1)
    m2 = P.decrypt(c2)

    # print(m1)
    # print(c1)
    # print(m2)

    print(P.is_homomorphic(c_sum,c1,c2))