from ..models.cifrador_homomorfico_completo import CifradorHomomorficoCompleto
from numpy.testing import assert_almost_equal

CKKS_PARAMS = {
    'scheme': 'CKKS',  # can also be 'ckks'
    'n': 2 ** 14,  # Polynomial modulus degree. For CKKS, n/2 values can be
    #  encoded in a single ciphertext.
    #  Typ. 2^D for D in [10, 15]
    'scale': 2 ** 30,  # All the encodings will use it for float->fixed point
    #  conversion: x_fix = round(x_float * scale)
    #  You can use this as default scale or use a different
    #  scale on each operation (set in HE.encryptFrac)
    'qi_sizes': [60, 30, 30, 30, 60]  # Number of bits of each prime in the chain.
    # Intermediate values should be  close to log2(scale)
    # for each operation, to have small rounding errors.
}


def test_cifrador_homomorfico_completo_encripta_un_mensaje():
    numero_a_encriptar = 5
    cifrador_homomorfico = CifradorHomomorficoCompleto()
    numero_encriptado = cifrador_homomorfico.encriptar(numero_a_encriptar)
    assert numero_encriptado != numero_a_encriptar


def test_cifrador_homomorfico_completo_desencripta_un_mensaje():
    numero_a_encriptar = 5
    cifrador_homomorfico_completo = CifradorHomomorficoCompleto()
    numero_encriptado = cifrador_homomorfico_completo.encriptar(numero_a_encriptar)
    numero_desencriptado = cifrador_homomorfico_completo.desencriptar(numero_encriptado)
    assert numero_a_encriptar == numero_desencriptado


def test_suma_de_un_numero_encriptado_y_uno_no_encriptado():
    numero_a_encriptar = 10
    numero_no_encriptado = 5

    cifrador_homomorfico_completo = CifradorHomomorficoCompleto()

    numero_encriptado = cifrador_homomorfico_completo.encriptar(numero_a_encriptar)

    suma_encriptada = numero_encriptado + numero_no_encriptado
    suma_desencriptada = cifrador_homomorfico_completo.desencriptar(suma_encriptada)

    assert suma_desencriptada == 15


def test_suma_de_dos_numeros_encriptados():
    numero_a_encriptar_1 = 10
    numero_a_encriptar_2 = 5

    cifrador_homomorfico_completo = CifradorHomomorficoCompleto()

    numero_encriptado_1 = cifrador_homomorfico_completo.encriptar(numero_a_encriptar_1)
    numero_encriptado_2 = cifrador_homomorfico_completo.encriptar(numero_a_encriptar_2)

    suma_encriptada = numero_encriptado_1 + numero_encriptado_2
    suma_desencriptada = cifrador_homomorfico_completo.desencriptar(suma_encriptada)

    assert suma_desencriptada == 15


def test_multiplicacion_de_un_numero_encriptado_por_numero_no_encriptado():
    numero_a_encriptar_1 = 5
    numero_2 = 5

    cifrador_homomorfico_completo = CifradorHomomorficoCompleto()
    numero_encriptado_1 = cifrador_homomorfico_completo.encriptar(numero_a_encriptar_1)
    multiplicacion_encriptada = numero_encriptado_1 * numero_2
    multiplicacion_desencriptada = cifrador_homomorfico_completo.desencriptar(multiplicacion_encriptada)

    assert multiplicacion_desencriptada == 25


def test_multiplicacion_de_dos_numeros_encriptados():
    numero_a_encriptar_1 = 10
    numero_a_encriptar_2 = 5

    cifrador_homomorfico_completo = CifradorHomomorficoCompleto()

    numero_encriptado_1 = cifrador_homomorfico_completo.encriptar(numero_a_encriptar_1)
    numero_encriptado_2 = cifrador_homomorfico_completo.encriptar(numero_a_encriptar_2)

    multiplicacion_encriptada = numero_encriptado_1 * numero_encriptado_2
    multiplicacion_desencriptada = cifrador_homomorfico_completo.desencriptar(multiplicacion_encriptada)

    assert multiplicacion_desencriptada == 50


def test_cifrador_homomorfico_completo_encripta_un_mensaje_float():
    numero_a_encriptar = 5.6

    cifrador_homomorfico = CifradorHomomorficoCompleto(context_gen_params=CKKS_PARAMS)
    numero_encriptado = cifrador_homomorfico.encriptar(numero_a_encriptar)

    assert numero_encriptado != numero_a_encriptar


def test_cifrador_homomorfico_completo_desencipta_un_mensaje_float():
    numero_a_encriptar = 5.5

    cifrador_homomorfico_completo = CifradorHomomorficoCompleto(context_gen_params=CKKS_PARAMS)
    numero_encriptado = cifrador_homomorfico_completo.encriptar(numero_a_encriptar)

    numero_desencriptado = cifrador_homomorfico_completo.desencriptar(numero_encriptado)
    assert_almost_equal(numero_desencriptado, numero_a_encriptar, decimal=5, err_msg="Precision muy mala", verbose=True)
