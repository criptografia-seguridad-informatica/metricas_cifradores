from Pyfhel import Pyfhel
import numpy as np

CKKS_PARAMS = {
    'scheme': 'CKKS',  # can also be 'ckks'
    'n': 2 ** 14,  # Polynomial modulus degree. For CKKS, n/2 values can be
    #  encoded in a single ciphertext.
    #  Typ. 2^D for D in [10, 15]
    'scale': 2 ** 30,  # All the encodings will use it for float->fixed point
    #  conversion: x_fix = round(x_float * scale)
    #  You can use this as default scale or use a different
    #  scale on each operation (set in HE.encryptFrac)
    'qi_sizes': [60, 30, 30, 30, 60],  # Number of bits of each prime in the chain.
    # Intermediate values should be  close to log2(scale)
    # for each operation, to have small rounding errors.
    'sec': 256

}

BFV_PARAMS = {'scheme': 'bfv', 'n': 2 ** 14, 't_bits': 20, 'sec': 256}


class CifradorHomomorficoCompleto:
    """
    Una clase que implementa encriptación homomórfica completa.
    """

    def __init__(self, context_gen_params=None):
        if context_gen_params is None or context_gen_params == 'BFV':
            context_gen_params = BFV_PARAMS
        elif context_gen_params == 'CKKS':
            context_gen_params = CKKS_PARAMS

        fhe = Pyfhel()
        fhe.contextGen(**context_gen_params)
        fhe.keyGen()
        self.__scheme = context_gen_params['scheme']
        self.__fhe = fhe

    def encriptar(self, numero_a_encriptar):
        if self.__scheme == 'bfv':
            integer_number = np.array([numero_a_encriptar], dtype=np.int64)
            return self.__fhe.encryptInt(integer_number)
        else:
            float_number = np.array([numero_a_encriptar], dtype=np.float64)
            encoded_float = self.__fhe.encodeFrac(float_number)
            return self.__fhe.encryptPtxt(encoded_float)

    def desencriptar(self, numero_a_desencriptar):
        if self.__scheme == 'bfv':
            return self.__fhe.decryptInt(numero_a_desencriptar)[0]
        else:
            return self.__fhe.decryptFrac(numero_a_desencriptar)[0]
