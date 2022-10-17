import gmpy2
import random

rand_lim = pow(10,10)
rand = gmpy2.random_state(hash(gmpy2.random_state()))


def generate_prime(bits):
    while True:
        p = gmpy2.mpz(2)**(bits-1) + gmpy2.mpz_urandomb(rand, (bits-1))
        if gmpy2.is_prime(p):
            return p


def get_ranged_random_integer(rand_min, rand_max):
    rs = gmpy2.random_state(random.randint(0,rand_lim))
    return rand_min + gmpy2.mpz_random(rs, rand_max - rand_min + 1)

