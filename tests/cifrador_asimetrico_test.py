from ..models.cifrador_asimetrico import CifradorAsimetrico


def test_cifrador_asimetrico_encripta_mensaje():
    numero_a_encriptar = 5
    cifrador_asimetrico = CifradorAsimetrico()

    numero_encriptado = cifrador_asimetrico.encriptar(numero_a_encriptar)

    assert numero_encriptado != numero_a_encriptar


def test_cifrador_asimetrico_desencripta_un_mensaje():
    numero_a_encriptar = 5
    cifrador_asimetrico = CifradorAsimetrico()

    numero_encriptado = cifrador_asimetrico.encriptar(numero_a_encriptar)
    numero_desencriptado = cifrador_asimetrico.desencriptar(numero_encriptado)

    assert numero_desencriptado == numero_a_encriptar
