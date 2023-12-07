from Pyfhel import Pyfhel
import numpy as np


class CifradorHomomorficoCompleto:
    """
    Una clase que implementa encriptación homomórfica completa.
    """

    def __init__(self, context_gen_params=None):
        if context_gen_params is None:
            context_gen_params = {'scheme': 'bfv', 'n': 2 ** 14, 't_bits': 20}
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
            return self.__fhe.decodeFrac(numero_a_desencriptar)[0]
