from threading import Thread
from random import randint, choice
from sys import stderr
from aes import plaintextToState, keyExpansion, addRoundKey, subBytes, shiftRows, mixColumns, stateToHexCipher, \
    hexCipherToState, RoundConst, Sbox, hex_to_ascii, InvSbox


def encryption(plaintext: str, key: str, mode: str = "ECB", IV=None) -> str:
    blocks: list[list[list[int]]] = plaintextToState(plaintext)
    w: list[list[int]]
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

    print(f'Klucz ostatniej rundy {w[-4:]}')

    return cipher


def encryptionDFA(plaintext: str, key: str, DFArow: int, DFAcol: int, DFAval: int) -> str:
    blocks: list[list[list[int]]] = plaintextToState(plaintext)
    w: list[list[int]]
    numOfRounds: int
    w, numOfRounds = keyExpansion(key)
    for block in blocks:
        block = addRoundKey(block, w, 0)

        for i in range(1, numOfRounds):
            block = subBytes(block)
            block = shiftRows(block)
            block = mixColumns(block)
            block = addRoundKey(block, w, i)

        # Fault Injection
        block[DFArow][DFAcol] ^= DFAval

        block = subBytes(block)
        block = shiftRows(block)
        block = addRoundKey(block, w, numOfRounds)

    cipher: str = stateToHexCipher(blocks)

    return cipher


def encryptionDFARedundant(plaintext: str, key: str, DFA: bool = True,
                           DFArow: int = 0, DFAcol: int = 0, DFAval: int = 1,
                           howManyRegRounsInRedundancy: int = 0) -> str:
    blocks: list[list[list[int]]] = plaintextToState(plaintext)
    w: list[list[int]]
    numOfRounds: int
    w, numOfRounds = keyExpansion(key)
    for block in blocks:
        block = addRoundKey(block, w, 0)

        for i in range(1, numOfRounds - howManyRegRounsInRedundancy):
            block = subBytes(block)
            block = shiftRows(block)
            block = mixColumns(block)
            block = addRoundKey(block, w, i)

        blockA: list[list[int]] = []
        blockB: list[list[int]] = []

        for r in block:
            blockA.append([])
            blockB.append([])

            for c in r:
                blockA[-1].append(c)
                blockB[-1].append(c)

        def computeRounds(b: list[list[int]], block: int = 0, DFA: bool = False) -> list[list[int]]:

            for i in range(numOfRounds - howManyRegRounsInRedundancy, numOfRounds):
                b = subBytes(b)
                b = shiftRows(b)
                b = mixColumns(b)
                b = addRoundKey(b, w, i)

            if DFA:
                # Fault Injection
                b[DFArow][DFAcol] ^= DFAval

            b = subBytes(b)
            b = shiftRows(b)
            b = addRoundKey(b, w, numOfRounds)

            match block:
                case 0:
                    for j in range(4):
                        blockA[j] = b[j]

                case 1:
                    for j in range(4):
                        blockB[j] = b[j]

            return b

        # Rekomputacja ostatnich rund - z DFA ba A
        # computeRounds(blockA, block=0, DFA = DFA)
        # computeRounds(block, block=1)

        # Redundancja (zrónoleglenie obliczeń)
        tA : Thread = Thread(target=computeRounds, args=(blockA, 1, DFA))
        tB : Thread = Thread(target=computeRounds, args=(blockA, 0, DFA))

        tA.start()
        tB.start()

        tA.join()
        tB.join()

        # porówanie wyników
        for i, (rA, rB) in enumerate(zip(blockA, blockB)):
            for j, (cA, cB) in enumerate(zip(rA, rB)):
                if cA != cB:
                    print(f'Znaleziono niezgodność bajcie ({i}, {j}), czyli ({i}, {(i + j) % 4}) przed ShiftRows',
                          file=stderr)
                    return '--- ERROR - POTENTIAL ATTACK DETECTED ---'

        for i in range(4):
            block[i] = blockA[i]

    cipher: str = stateToHexCipher(blocks)

    return cipher


def recoverFragmentOfLastKey(correct: str, attacked: str, DFAval: int) -> tuple[list[int], int, int]:
    cor: list[list[list[int]]] = hexCipherToState(correct)
    att: list[list[list[int]]] = hexCipherToState(attacked)

    row: int = -1
    col: int = -1
    breaker: bool = False

    # znalezienie miejsca błędu
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
        return InvSbox[val // 16][val % 16]

    cVal: int = cor[0][row][col]
    aVal: int = att[0][row][col]

    # znalezienie kandydatów na bajt klucza
    possibleKeys: list[int] = []
    for key in range(256):
        if (invS(key ^ cVal) ^ invS(key ^ aVal)) == DFAval:
            possibleKeys.append(key)

    return possibleKeys, row, col


def invKeySchedule(lastKey: list[list[int]], keyNum: int) -> list[list[int]]:
    howManyKeys: int = 4 * (keyNum + 7)

    allKeys = [[0, 0, 0, 0] for _ in range(howManyKeys)]
    allKeys[-4:] = lastKey

    # expand key dla pierwszego klucza bloku
    def expandKey(word: list[int], round: int) -> list[int]:
        word: list[int] = word[1:] + word[:1]
        for i in range(4):
            row: int = word[i] // 16
            col: int = word[i] % 16
            word[i] = Sbox[row][col]
        word[0] = word[0] ^ RoundConst[round]
        return word

    # cofanie się w kluczach
    for i in range(howManyKeys - 5, -1, -1):
        if i % 4 != 0:
            for j in range(4):
                allKeys[i][j] = allKeys[i + keyNum][j] ^ allKeys[i + keyNum - 1][j]

        else:
            expanded: list[int] = expandKey(allKeys[i + keyNum - 1], i // keyNum + 1)
            for j in range(4):
                allKeys[i][j] = allKeys[i + keyNum][j] ^ expanded[j]

    return allKeys[:keyNum]


def getMainKey(keyHex: str = '000102030405060708090a0b0c0d0e0f',
               plainTextHex: str = '00112233445566778899aabbccddeeff') -> str:
    key: str = hex_to_ascii(keyHex)
    plaintext: str = hex_to_ascii(plainTextHex)

    print(f'Klucz glówny')
    print(keyHex)

    correct: str = encryption(plaintext, key)

    print('Poprwny szyfrogram')
    print(correct)

    DFArow: int
    DFAcol: int
    DFAval: int

    lastRoundKey: list[list[int]] = [[], [], [], []]

    possibleKeys: list[int] = []
    print('')

    for i in range(16):
        DFAval = randint(1, 255)
        attacked: str = encryptionDFA(plaintext, key, i // 4, i % 4, DFAval)

        possibleKeys, DFArow, DFAcol = recoverFragmentOfLastKey(correct, attacked, DFAval)

        print(f'Atak na bajt klucza {DFArow} {DFAcol}')
        print(attacked)
        print(f'Możliwe bajty klucza : {possibleKeys}')

        if len(possibleKeys) > 1:
            DFAval = randint(1, 255)
            attacked: str = encryptionDFA(plaintext, key, i // 4, i % 4, DFAval)
            possibleKeys = list(set(recoverFragmentOfLastKey(correct, attacked, DFAval)[0]) & set(possibleKeys))
            print(attacked)
            print(f'Możliwe bajty klucza : {possibleKeys}')

        lastRoundKey[DFAcol].append(possibleKeys[0])
        print('')

    print(f'Klucz ostaniej rundy : {lastRoundKey}')

    mainKey: list[list[int]] = invKeySchedule(lastRoundKey, 4)
    k: str = ''
    for w in mainKey:
        for b in w:
            k += str(hex(b))[2:].rjust(2, '0')

    print('Klucz główny')
    print(k)
    print(keyHex)

    print('')

    return k


if __name__ == '__main__':
    key: str = ''.join(choice("0123456789abcdef") for _ in range(32))
    plaintext: str = ''.join(choice("0123456789abcdef") for _ in range(32))

    getMainKey(key, plaintext)

    print(encryptionDFARedundant(plaintext, key, DFA=True, DFArow=0, DFAcol=0, DFAval=1))
