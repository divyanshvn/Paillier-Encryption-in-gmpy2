from cgi import print_arguments
import gmpy2
from Private_Key import PrivateKey
from gmpy_prime import *

bit_lengths = [16,32,128,512,1024]

def prime_tester():
    '''
    generating n random prime integers, testing if they are all prime and are not repetitive
    '''
    n = 500

    for bit_length in bit_lengths:
        mod_list = set([])
        x = get_ranged_random_integer(int(pow(2,bit_length/8)),int(pow(2,bit_length/4)))

        for i in range(n):
            p = generate_prime(bit_length)
            mod_list.add(p%x)
        
        if len(mod_list) > 1:       # This is done to ensure consistent behaviour of the pseudo random number generator
            print("Generated 500 random prime numbers successfully of bit length %d"%(bit_length))
        
        else:
            print("Inconsistent Behaviour by Pseudo Random Generator for bit length %d"%(bit_length))
    return

def decryption_tester():
    '''
    iterating over bit lengths, for n random messages, compute the ciphertext and then decrypt it and confirm that the decrypted plain text is the same as the original message
    '''
    total_primes = 10
    total_messages = 50

    for bit_length in bit_lengths:
        
        n_list = set([])

        for i in range(total_primes):
            P = PrivateKey()
            P.key_gen(bit_length)       # Creating an Instance of the class PrivateKey 
            n_list.add(P.n)

            for j in range(total_messages):
                plain = get_ranged_random_integer(int(pow(2,bit_length/4)),int(pow(2,bit_length/2)))
                cipher = P.encrypt(plain)
                plain_new = P.decrypt(cipher)

                if(plain_new != plain):
                    print("Error in Encryption and Decryption with bit length %d, plain text %s and decrypted plain text as %s"%(bit_length,str(plain),str(plain_new)))
                    # print(cipher)
                    return
            
        if(len(n_list) == 1):
            print("Inconsistent Behaviour : Key Generation not randomly uniform")

        else:
            print("Successful Encryption-Decryption for bit length %d"%(bit_length))
    
    return


def homo_tester():
    '''
    iterate over bit lengths , for n random message1 and message2, compute c1*c2, then decrypt it and check if decr(.) = m1 + m2 
    '''
    total_primes = 10
    total_messages = 50

    for bit_length in bit_lengths:
        
        n_list = set([])

        for i in range(total_primes):
            P = PrivateKey()
            P.key_gen(bit_length)       # Creating an Instance of the class PrivateKey 
            n_list.add(P.n)

            for j in range(total_messages):
                plain1 = get_ranged_random_integer(int(pow(2,bit_length/4)),int(pow(2,bit_length/2)))
                plain2 = get_ranged_random_integer(int(pow(2,bit_length/4)),int(pow(2,bit_length/2)))

                cipher1 = P.encrypt(plain1)
                cipher2 = P.encrypt(plain2)
                cipher_sum = P.add_homo(cipher1,cipher2)

                if not P.is_homomorphic(cipher_sum, cipher1, cipher2):
                    print("Error in Homomorphic Property for bit length %d"%(bit_length))


        else:
            print("Verified Homomosrphic Addition for bit length %d"%(bit_length))
    
    return

prime_tester()
decryption_tester()
homo_tester()