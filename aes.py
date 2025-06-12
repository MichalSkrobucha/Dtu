# https://gist.github.com/bonsaiviking/5571001
# Lepiej nie brać 1:1 żebyśmy wiedzieli lepiej jak działa nasz AES

import random
import string
import sys

Sbox: list[list[int]] = [
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

InvSbox: list[list[int]] = [
    [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251],
    [124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203],
    [84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78],
    [8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37],
    [114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146],
    [108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132],
    [144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6],
    [208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107],
    [58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115],
    [150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110],
    [71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27],
    [252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244],
    [31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95],
    [96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239],
    [160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97],
    [23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]
]

Rcon: list[int] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]  # ??? - co to jest

MixColumnsMatrix: list[list[int]] = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
]

InvMixColumnsMatrix: list[list[int]] = [
    [14, 11, 13, 9],
    [9, 14, 11, 13],
    [13, 9, 14, 11],
    [11, 13, 9, 14]
]

State: list[list[int]] = [[0 for x in range(4)] for y in range(4)]


def keyGen(keySize: int) -> str:
    key: str = ""

    if keySize not in [128, 192, 256]:
        print("Klucz musi być 16-24-36-bitowy")
        sys.exit()

    for _ in range(keySize // 8):
        key += random.choice(string.hexdigits)

    return key


def keyExpansion(key) -> (list[list[int]], int):
    keySize: int = len(key)

    Nk: int = keySize // 4  # ??? - co to jest
    numOfRounds: int = Nk + 6

    w: list[list[int]] = []  # ???
    for i in range(Nk):
        w.append([ord(key[4 * i + j]) for j in range(4)])

    # ??? - co to robi
    def g(word: list[int], round: int) -> list[int]:
        word: list[int] = word[1:] + word[:1]
        for i in range(4):
            row: int = word[i] // 16
            col: int = word[i] % 16
            word[i] = Sbox[row][col]
        word[0] = word[0] ^ Rcon[round]
        return word

    for i in range(Nk, 4 * (numOfRounds + 1)):
        if i % Nk == 0:
            w.append([w[i - Nk][j] ^ g(w[i - 1], i // Nk)[j] for j in range(4)])
        else:
            w.append([w[i - Nk][j] ^ w[i - 1][j] for j in range(4)])

    return w, numOfRounds


def addRoundKey(state: list[list[int]], w: list[list[int]], round: int) -> list[list[int]]:
    for i in range(4):
        for j in range(4):
            state[i][j] = state[i][j] ^ w[round * 4 + j][i]
    return state


def subBytes(state: list[list[int]]) -> list[list[int]]:
    for i in range(4):
        for j in range(4):
            row: int = state[i][j] // 16
            col: int = state[i][j] % 16
            state[i][j] = Sbox[row][col]
    return state


def invSubBytes(state: list[list[int]]) -> list[list[int]]:
    for i in range(4):
        for j in range(4):
            row: int = state[i][j] // 16
            col: int = state[i][j] % 16
            state[i][j] = InvSbox[row][col]
    return state


def shiftRows(state: list[list[int]]) -> list[list[int]]:
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]
    return state


def invShiftRows(state: list[list[int]]) -> list[list[int]]:
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]
    return state


# ??? - co to robi
def gm(a: int, b: int) -> int:
    irreducible: int = 0x11b
    fx: int = a
    gx: int = b
    result: int = 0
    while gx:
        if gx & 1:
            result ^= fx
        fx <<= 1
        if fx & 0x100:
            fx ^= irreducible
        gx >>= 1
    return result


def mixColumns(state: list[list[int]]) -> list[list[int]]:
    for i in range(4):
        col: list[int] = [state[j][i] for j in range(4)]
        for j in range(4):
            state[j][i] = (gm(MixColumnsMatrix[j][0], col[0]) ^ gm(MixColumnsMatrix[j][1], col[1])
                           ^ gm(MixColumnsMatrix[j][2], col[2]) ^ gm(MixColumnsMatrix[j][3], col[3]))
    return state


def invMixColumns(state: list[list[int]]) -> list[list[int]]:
    for i in range(4):
        col: list[int] = [state[j][i] for j in range(4)]
        for j in range(4):
            state[j][i] = gm(InvMixColumnsMatrix[j][0], col[0]) ^ gm(InvMixColumnsMatrix[j][1], col[1]) ^ gm(
                InvMixColumnsMatrix[j][2], col[2]) ^ gm(InvMixColumnsMatrix[j][3], col[3])
    return state


def decTohex(dec: int) -> str:
    return hex(dec)[2:].zfill(2)


# No usages
# def AsciiToHex(key):
#     lm = []
#     for l in key:
#         lm.append([decTohex(i) for i in l])
#     print(lm)
#     return lm


def plaintextToState(plaintext: str) -> list[list[list[int]]]:
    blocks: list[str] = []
    states: list[list[list[int]]] = []
    for i in range(0, len(plaintext), 16):
        blocks.append(plaintext[i:i + 16])
    if (len(blocks[-1]) < 16):
        blocks[-1] += "0" * (16 - len(blocks[-1]))

    for block in blocks:
        state: list[list[int]] = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                state[j].append(ord(block[4 * i + j]))
        states.append(state)
    return states


def stateToPlaintext(states: list[list[list[int]]]) -> str:
    plaintext: str = ""
    for state in states:
        for i in range(4):
            for j in range(4):
                plaintext += chr(state[j][i])
    return plaintext


def stateToHexCipher(states: list[list[list[int]]]) -> str:
    cipher: str = ""
    for state in states:
        for i in range(4):
            for j in range(4):
                cipher += decTohex(state[j][i])
    return cipher


def hexCipherToState(cipher: str) -> list[list[list[int]]]:
    blocks: list[str] = []
    states: list[list[list[int]]] = []
    for i in range(0, len(cipher), 32):
        blocks.append(cipher[i:i + 32])
    for block in blocks:
        state: list[list[int]] = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                state[j].append(int(block[8 * i + 2 * j:8 * i + 2 * j + 2], 16))
        states.append(state)

    return states


# Na razie proponuję tylko ECB
def encryption(plaintext: str, key: str, mode: str = "ECB", IV=None):
    # if mode == "ECB":
    blocks: list[list[list[int]]] = plaintextToState(plaintext)
    w: list[list[int]]  # ???
    numOfRounds: int
    w, numOfRounds = keyExpansion(key)
    for block in blocks:
        block = addRoundKey(block, w, 0)
        for i in range(1, numOfRounds):
            block = subBytes(block)
            block = shiftRows(block)
            block = mixColumns(block)
            block = addRoundKey(block, w, i)
        block = subBytes(block)
        block = shiftRows(block)
        block = addRoundKey(block, w, numOfRounds)
    cipher: str = stateToHexCipher(blocks)
    return cipher, IV


# elif mode == "CBC":
#     blocks = plaintextToState(plaintext)
#     w, Nr = keyExpansion(key)
#     IV = [[random.randint(0, 255) for i in range(4)] for j in range(4)]
#     nIV = IV
#     for block in blocks:
#         for i in range(4):
#             for j in range(4):
#                 block[i][j] ^= IV[i][j]
#         block = addRoundKey(block, w, 0)
#         for i in range(1, Nr):
#             block = subBytes(block)
#             block = shiftRows(block)
#             block = mixColumns(block)
#             block = addRoundKey(block, w, i)
#         block = subBytes(block)
#         block = shiftRows(block)
#         block = addRoundKey(block, w, Nr)
#         IV = block
#     cipher = stateToHexCipher(blocks)
#     return cipher, nIV


def decryption(cipher: str, key: str, mode: str = "ECB", IV=None) -> str:
    # if mode == "ECB":
    w: list[list[int]]  # ???
    numOfRounds: int
    w, numOfRounds = keyExpansion(key)
    blocks = hexCipherToState(cipher)
    for block in blocks:
        block = addRoundKey(block, w, numOfRounds)
        block = invShiftRows(block)
        block = invSubBytes(block)
        for i in range(numOfRounds - 1, 0, -1):
            block = addRoundKey(block, w, i)
            block = invMixColumns(block)
            block = invShiftRows(block)
            block = invSubBytes(block)
        block = addRoundKey(block, w, 0)
    plaintext: str = stateToPlaintext(blocks)
    return plaintext


# elif mode == "CBC":
#     IV = hexCipherToState(IV)[0]
#     w, Nr = keyExpansion(key)
#     blocks = hexCipherToState(cipher)
#
#     for block in blocks:
#         nIV = [[block[i][j] for j in range(4)] for i in range(4)]
#         block = addRoundKey(block, w, Nr)
#         block = invShiftRows(block)
#         block = invSubBytes(block)
#         for i in range(Nr - 1, 0, -1):
#             block = addRoundKey(block, w, i)
#             block = invMixColumns(block)
#             block = invShiftRows(block)
#             block = invSubBytes(block)
#         block = addRoundKey(block, w, 0)
#         for i in range(4):
#             for j in range(4):
#                 block[i][j] ^= IV[i][j]
#         IV = nIV
#     plaintext = stateToPlaintext(blocks)
#     return plaintext


def hex_to_ascii(hex_string: str) -> str:
    return bytes.fromhex(hex_string).decode('latin1')


if __name__ == '__main__':
    # key = keyGen(128)
    key_hex = "000102030405060708090a0b0c0d0e0f"
    plaintext_hex = "00112233445566778899aabbccddeeff"
    key = hex_to_ascii(key_hex)
    plaintext = hex_to_ascii(plaintext_hex)
    print("Klucz ", key.encode('latin1').hex())
    print("Plaintext :", plaintext.encode('latin1').hex())

    # Ataki przeprowadaza się tak samo w CBC i ECB (?)
    # Więc proponuję tylko ECb (łatwiej)

    cipher, iv = encryption(plaintext, key)
    print("Zaszyfrowany tekst:", cipher)

    decrypted = decryption(cipher, key)
    print("Odszyfrowany tekst :", decrypted.encode('latin1').hex())

    print(plaintext == decrypted)
