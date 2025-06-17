import copy
from asyncio import wait_for

from aes import plaintextToState, addRoundKey, shiftRows, mixColumns, stateToHexCipher, hex_to_ascii, decryption, \
    keyExpansion
import hashlib

# dla jasności kodu użyto 1 s-boxa ale powinny być rózne ich kopie
Sbox1: list[list[int]] = [
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192],
    [183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21],
    [4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117],
    [9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132],
    [83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207],
    [208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168],
    [81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210],
    [205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115],
    [96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219],
    [224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121],
    [231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8],
    [186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138],
    [112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158],
    [225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223],
    [140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]
]

Sbox_dmg: list[list[int]] = [
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
]


# Funkcja pomocnicza: spłaszczanie 2D Sboxa
def flatten_sbox(sbox_2d):
    return [byte for row in sbox_2d for byte in row]

# Tryb 1: Wydajny - hash S-boxa
def check_sbox_hash(sbox, known_hash_hex):
    current_hash = hashlib.sha256(bytes(flatten_sbox(sbox))).hexdigest()
    if current_hash != known_hash_hex:
        print("[!!!] Wykryto manipulację w S-boxie (HASH NIEZGODNY)")
        return False
    return True

# subBytes z podanym S-boxem
def custom_sbox_subbytes(state, sbox_2d):
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            row = byte // 16
            col = byte % 16
            state[i][j] = sbox_2d[row][col]
    return state

def safe_subbytes_with_verification(state, sboxes):
    results = []
    for sbox in sboxes:
        temp_state = copy.deepcopy(state)  # Unikamy in-place modyfikacji
        result = custom_sbox_subbytes(temp_state, sbox)
        results.append(result)

    # Porównaj wszystkie wyniki
    first = results[0]
    for res in results[1:]:
        if res != first:
            print("[!!!] Wykryto niespójność wyników subBytes – możliwa manipulacja S-boxem!")
            return res, False

    return first, True


def encryption(plaintext: str, key: str, mode: str = "ECB", IV=None, security: str = "safe", faulty_round: int | None = None) -> str:
    blocks: list[list[list[int]]] = plaintextToState(plaintext)
    w: list[list[int]]
    numOfRounds: int
    w, numOfRounds = keyExpansion(key)

    for block_index in range(len(blocks)):
        block = blocks[block_index]  # teraz jawnie modyfikujemy ten blok

        block = addRoundKey(block, w, 0)
        for i in range(1, numOfRounds):
            use_damaged = (i == faulty_round)
            sbox_to_use = Sbox_dmg if use_damaged else Sbox1

            if security == "safe":
                if not check_sbox_hash(sbox_to_use, known_hash):
                    print(f"[!] Blok {block_index}, runda {i}: Nieprawidłowy S-box! Kontynuuję (propagacja błędu).")
                block = custom_sbox_subbytes(block, sbox_to_use)

            elif security == "efficient":
                sboxes = [Sbox1, Sbox1, Sbox_dmg] if use_damaged else [Sbox1, Sbox1, Sbox1]
                block, valid = safe_subbytes_with_verification(block, sboxes)
                if not valid:
                    print(
                        f"[!!!] Blok {block_index}, runda {i}: Wykryto niespójność subBytes! Możliwa manipulacja S-boxem.")

            block = shiftRows(block)
            block = mixColumns(block)
            block = addRoundKey(block, w, i)

        # Ostatnia runda
        use_damaged = (numOfRounds == faulty_round)
        sbox_to_use = Sbox_dmg if use_damaged else Sbox1

        if security == "safe":
            if not check_sbox_hash(sbox_to_use, known_hash):
                print(f"[!] Blok {block_index}, ostatnia runda: Nieprawidłowy S-box!")
            block = custom_sbox_subbytes(block, sbox_to_use)

        elif security == "efficient":
            sboxes = [Sbox1, Sbox1, Sbox_dmg] if use_damaged else [Sbox1, Sbox1, Sbox1]
            block, valid = safe_subbytes_with_verification(block, sboxes)
            if not valid:
                print(f"[!!!] Blok {block_index}, ostatnia runda: Wykryto niespójność subBytes!")

        block = shiftRows(block)
        block = addRoundKey(block, w, numOfRounds)
        blocks[block_index] = block

    cipher: str = stateToHexCipher(blocks)
    return cipher


if __name__ == '__main__':
    known_hash = hashlib.sha256(bytes(flatten_sbox(Sbox1))).hexdigest()
    # key = keyGen(128)
    key_hex: str = "000102030405060708090a0b0c0d0e0f"
    plaintext_hex: str = "00112233445566778899aabbccddeeff"
    key: str = hex_to_ascii(key_hex)
    plaintext: str = hex_to_ascii(plaintext_hex)
    print("Klucz ", key.encode('latin1').hex())
    print("Plaintext :", plaintext.encode('latin1').hex())

    cipher: str = encryption(plaintext, key, security="safe", faulty_round=1)
    print("Zaszyfrowany tekst:", cipher)

    decrypted: str = decryption(cipher, key)
    print("Odszyfrowany tekst :", decrypted.encode('latin1').hex())

    cipher: str = encryption(plaintext, key, security="efficient", faulty_round=1)
    print("Zaszyfrowany tekst:", cipher)

    decrypted: str = decryption(cipher, key)
    print("Odszyfrowany tekst :", decrypted.encode('latin1').hex())