from random import randint

from aes import plaintextToState, keyExpansion, addRoundKey, subBytes, shiftRows, mixColumns, stateToHexCipher, \
    hex_to_ascii, encryption, hexCipherToState, InvSbox, RoundConst, Sbox, decryption

def KeyResetAttack(key, plaintext):
    faulty_key = hex_to_ascii("00" * 16)
    cipher = encryption(plaintext, key, mode="ECB")
    print("Otrzymany szyfrogram: ", cipher)
    decrypted = decryption(cipher, faulty_key, mode="ECB")
    print("--------------------------")
    #print(plaintext.encode('latin1').hex())
    #print(decrypted.encode('latin1').hex())
    binary1 = ''.join(format(ord(b), '08b') for b in plaintext)
    binary2 = ''.join(format(ord(b), '08b') for b in decrypted)
    print("Wiadomość: ")
    print(binary1)
    print("Szyfr: ")
    print(binary2)
    x=0
    for i in range(len(binary1)):
        if binary1[i]==binary2[i]:
            x+=1
    print("Liczba wszystkich bitów", len(binary1))
    print("Liczba zgodnych bitów",x)

def detect_duplicate_cipher_blocks(ciphertext: bytes, block_size: int = 16) -> bool:
    """Wykrywa powtarzające się bloki w szyfrogramie (np. dla CBC bez losowego IV)."""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    unique_blocks = set(blocks)
    return len(unique_blocks) != len(blocks)  # True jeśli są duplikaty

def secure_encrypt_cbc(plaintext: bytes, key: bytes) -> bytes:
    """Szyfruje plaintext w CBC z losowym IV i dokleja IV na początek."""
    iv = os.urandom(16)  # 128-bitowy IV
    ciphertext = encrypt_cbc(plaintext, key, iv)
    return iv + ciphertext  # IV || CIPHERTEXT
def secure_decrypt_cbc(ciphertext_with_iv: bytes, key: bytes) -> bytes:
    """Deszyfruje szyfrogram zakodowany jako IV || CIPHERTEXT"""
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]
    return decrypt_cbc(ciphertext, key, iv)


key_hex = "000102030405060708090a0b0c0d0e0f"
plaintext_hex = "00112233445566778899aabbccddeeff"
key = hex_to_ascii(key_hex)
plaintext = hex_to_ascii(plaintext_hex)
print("Klucz ", key.encode('latin1').hex())
print("Plaintext :", plaintext.encode('latin1').hex())
#byte_index_to_reset
#print(f"\n=== Symulacja ataku: Reset bajtu klucza na pozycji {byte_index_to_reset} ===")
KeyResetAttack(key, plaintext)
print("-------------------------------------------")
import os
import hashlib
import random
import copy

# EEPROM: przechowuje klucz i sumę kontrolną
class EEPROM:
    def __init__(self, key: bytes):
        self.key = key
        self.checksum = self._calculate_checksum(key)

    def _calculate_checksum(self, key: bytes) -> bytes:
        # Można zamienić na HMAC/SHA256 z kluczem systemowym
        return hashlib.sha256(key).digest()

    def read_key(self) -> tuple[bytes, bytes]:
        return self.key, self.checksum

# RAM: próbuje bezpiecznie odczytać klucz z EEPROM
class RAM:
    def __init__(self):
        self.key = None

    def load_key(self, eeprom: EEPROM, inject_fault: bool = False) -> bool:
        raw_key, checksum = eeprom.read_key()

        # Symulujemy potencjalny błąd bitowy w trakcie kopiowania
        copied_key = copy.deepcopy(raw_key)
        if inject_fault:
            copied_key = self._inject_fault(copied_key)

        # Sprawdzenie integralności
        calculated_checksum = hashlib.sha256(copied_key).digest()
        if calculated_checksum == checksum:
            self.key = copied_key
            print("Klucz załadowany poprawnie.")
            return True
        else:
            print("Wykryto błąd podczas kopiowania klucza! Ładowanie przerwane.")
            return False

    def _inject_fault(self, data: bytes) -> bytes:
        data = bytearray(data)
        index = random.randint(0, len(data) - 1)
        bit = 1 << random.randint(0, 7)
        data[index] ^= bit  # Flipping a random bit
        return bytes(data)

# --- Przykład działania ---

eeprom = EEPROM(key=os.urandom(32))  # 256-bitowy klucz AES
ram = RAM()

print("\nPróba bezpiecznego kopiowania (bez zakłóceń):")
ram.load_key(eeprom, inject_fault=False)

print("\nPróba kopiowania z błędem:")
ram.load_key(eeprom, inject_fault=True)