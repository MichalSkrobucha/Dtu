from random import randint, choice

import aes
from aes import plaintextToState, keyExpansion, addRoundKey, subBytes, shiftRows, mixColumns, stateToHexCipher, \
    hexCipherToState, RoundConst, Sbox


def encryptionDFA(plaintext: str, key: str, DFArow: int, DFAcol: int, DFAval: int, mode: str = "ECB", IV=None) -> str:
    # if mode == "ECB":
    blocks: list[list[list[int]]] = plaintextToState(plaintext)
    w: list[list[int]]
    numOfRounds: int
    w, numOfRounds = keyExpansion(key)
    for block in blocks:
        block = addRoundKey(block, w, 0)

        # rundy początkowe

        for i in range(1, numOfRounds):
            block = subBytes(block)
            block = shiftRows(block)
            block = mixColumns(block)
            block = addRoundKey(block, w, i)

        # ostatnia runda
        # Fault injection
        # print(f'Atak na element ({DFArow}, {DFAcol}) maską xor {hex(DFAval)}')
        # print(f'Poprawna wartość klucza: {hex(w[-4:][(DFAcol - DFArow) % 4][DFArow])}')
        block[DFArow][DFAcol] ^= DFAval

        block = subBytes(block)
        block = shiftRows(block)
        block = addRoundKey(block, w, numOfRounds)

    cipher: str = stateToHexCipher(blocks)

    return cipher


def encryptionDFARedundant(plaintext: str, key: str, DFArow: int, DFAcol: int, DFAval: int,
                           mode: str = "ECB", IV=None) -> str:
    # if mode == "ECB":
    blocks: list[list[list[int]]] = plaintextToState(plaintext)
    w: list[list[int]]
    numOfRounds: int
    w, numOfRounds = keyExpansion(key)
    for block in blocks:
        block = addRoundKey(block, w, 0)

        # rundy początkowe

        for i in range(1, numOfRounds):
            block = subBytes(block)
            block = shiftRows(block)
            block = mixColumns(block)
            block = addRoundKey(block, w, i)

        # kopiowanie wartości ostatniego obliczonego stany
        blockA: list[list[int]] = []
        blockB: list[list[int]] = []

        for r in block:
            blockA.append([])
            blockB.append([])

            for c in r:
                blockA[-1].append(c)
                blockB[-1].append(c)

        def computeRounds(b: list[list[int]], DFA: bool = False) -> list[list[int]]:
            if DFA:
                print(f'Atak na element ({DFArow}, {DFAcol}) maską xor {hex(DFAval)}')
                print(f'Poprawna wartość klucza: {hex(w[-4:][(DFAcol - DFArow) % 4][DFArow])}')
                b[DFArow][DFAcol] ^= DFAval

            b = subBytes(b)
            b = shiftRows(b)
            return addRoundKey(b, w, numOfRounds)

        # 'Równioległe' liczenie ostatnich rund - z DFA ba B
        blockA = computeRounds(blockA)
        blockB = computeRounds(blockB, DFA=True)

        # porówanie wyników
        for i, (rA, rB) in enumerate(zip(blockA, blockB)):
            for j, (cA, cB) in enumerate(zip(rA, rB)):
                if cA != cB:
                    print(f'Znaleziono niezgodność bajcie ({i}, {j}), czyli ({i}, {(i + j) % 4}) przed ShiftRows')
                    return '--- ERROR - POTENTIAL ATTACK DETECTED ---'

        block = blockA

    cipher: str = stateToHexCipher(blocks)

    return cipher


def recoverFragmentOfLastKey(correct: str, attacked: str, DFAval: int) -> tuple[list[int], int, int]:
    cor: list[list[list[int]]] = hexCipherToState(correct)
    att: list[list[list[int]]] = hexCipherToState(attacked)

    row: int = -1
    col: int = -1
    breaker: bool = False

    for r in range(4):
        for c in range(4):
            if cor[0][r][c] != att[0][r][c]:
                row = r
                col = c

                breaker = True
                break

        if breaker:
            break

    def invS(val: int) -> int:
        return aes.InvSbox[val // 16][val % 16]

    cVal: int = cor[0][row][col]
    aVal: int = att[0][row][col]

    # print(row, col, hex(cVal), hex(aVal))

    possibleKeys: list[int] = []

    for key in range(256):
        if (invS(key ^ cVal) ^ invS(key ^ aVal)) == DFAval:
            possibleKeys.append(key)

    return possibleKeys, row, col


def invKeySchedule(lastKey: list[list[int]], keyNum: int) -> list[list[int]]:
    howManyKeys: int = 4 * (keyNum + 7)

    allKeys = [[0, 0, 0, 0] for _ in range(howManyKeys)]
    allKeys[-4:] = lastKey

    # 0 [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
    # 1 [[214, 170, 116, 253], [210, 175, 114, 250], [218, 166, 120, 241], [214, 171, 118, 254]]
    # 2 [[182, 146, 207, 11], [100, 61, 189, 241], [190, 155, 197, 0], [104, 48, 179, 254]]
    # 3 [[182, 255, 116, 78], [210, 194, 201, 191], [108, 89, 12, 191], [4, 105, 191, 65]]
    # 4 [[71, 247, 247, 188], [149, 53, 62, 3], [249, 108, 50, 188], [253, 5, 141, 253]]
    # 5 [[60, 170, 163, 232], [169, 159, 157, 235], [80, 243, 175, 87], [173, 246, 34, 170]]
    # 6 [[94, 57, 15, 125], [247, 166, 146, 150], [167, 85, 61, 193], [10, 163, 31, 107]]
    # 7 [[20, 249, 112, 26], [227, 95, 226, 140], [68, 10, 223, 77], [78, 169, 192, 38]]
    # 8 [[71, 67, 135, 53], [164, 28, 101, 185], [224, 22, 186, 244], [174, 191, 122, 210]]
    # 9 [[84, 153, 50, 209], [240, 133, 87, 104], [16, 147, 237, 156], [190, 44, 151, 78]]
    # 10 [[19, 17, 29, 127], [227, 148, 74, 23], [243, 7, 167, 139], [77, 43, 48, 197]]

    def expandKey(word: list[int], round: int) -> list[int]:
        word: list[int] = word[1:] + word[:1]
        for i in range(4):
            row: int = word[i] // 16
            col: int = word[i] % 16
            word[i] = Sbox[row][col]
        word[0] = word[0] ^ RoundConst[round]
        return word

    for i in range(howManyKeys - 5, -1, -1):

        if i % 4 != 0:

            for j in range(4):
                allKeys[i][j] = allKeys[i + keyNum][j] ^ allKeys[i + keyNum - 1][j]

        else:
            expanded : list[int] = expandKey(allKeys[i + keyNum - 1], i // keyNum + 1)

            for j in range(4):
                allKeys[i][j] = allKeys[i + keyNum][j] ^ expanded[j]

    return allKeys[:keyNum]


if __name__ == '__main__':
    key_hex: str = ''.join(choice("0123456789abcdef") for _ in range(32))
    key_hex: str = "000102030405060708090a0b0c0d0e0f"
    plaintext_hex: str = "00112233445566778899aabbccddeeff"
    key: str = aes.hex_to_ascii(key_hex)
    plaintext: str = aes.hex_to_ascii(plaintext_hex)
    correct: str = aes.encryption(plaintext, key)

    DFArow: int
    DFAcol: int
    DFAval: int # to musi być znane

    lastKeyCandidates: list[list[list[int]]] = [[[], [], [], []], [[], [], [], []], [[], [], [], []], [[], [], [], []]]

    possibleKeys: list[int] = []

    for i in range(16):
        DFAval = randint(1, 255)
        attacked: str = encryptionDFA(plaintext, key, i // 4, i % 4, DFAval)
        # print("Zaszyfrowany tekst:", attacked)

        # print(attacked)

        possibleKeys, DFArow, DFAcol = recoverFragmentOfLastKey(correct, attacked, DFAval)
        # print(f'Znaleziono bajt klucza: {DFAval} w word {DFAcol}, o indeksie {DFArow}')

        lastKeyCandidates[DFAcol][DFArow] = possibleKeys

    # print(lastKeyCandidates)

    manyValues: bool = False

    for w in lastKeyCandidates:
        for b in w:
            if len(b) > 1:
                manyValues = True
                break

    while manyValues:
        manyValues = False

        for i in range(16):
            DFAval = randint(1, 255)
            attacked: str = encryptionDFA(plaintext, key, i // 4, i % 4, DFAval)
            # print("Zaszyfrowany tekst:", attacked)

            # print(attacked)

            possibleKeys, DFArow, DFAcol = recoverFragmentOfLastKey(correct, attacked, DFAval)
            # print(f'Znaleziono bajt klucza: {DFAval} w word {DFAcol}, o indeksie {DFArow}')

            lastKeyCandidates[DFAcol][DFArow] = list(set(possibleKeys) & set(lastKeyCandidates[DFAcol][DFArow]))

        # print(lastKeyCandidates)

        for w in lastKeyCandidates:
            for b in w:
                if len(b) > 1:
                    manyValues = True
                    break

    lastRoundKey = [[b[0] for b in w] for w in lastKeyCandidates]

    print(invKeySchedule(lastRoundKey, 4))