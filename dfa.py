from random import randint

from aes import plaintextToState, keyExpansion, addRoundKey, subBytes, shiftRows, mixColumns, stateToHexCipher, \
    hex_to_ascii, encryption, hexCipherToState, InvSbox, RoundConst, Sbox


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
        print(f'Atak na element ({DFArow}, {DFAcol}) maską xor {hex(DFAval)}')
        print(f'Poprawna wartość klucza: {hex(w[-4:][(DFAcol - DFArow) % 4][DFArow])}')
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


def recoverRoundKey(correct: str, attacked: str, DFAval: int) -> tuple[int, int, int]:
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

    # print(row, col, delta)

    def invSBox(val: int) -> int:
        row: int = val // 16
        col: int = val % 16
        return InvSbox[row][col]

    cVal: int = cor[0][row][col]
    aVal: int = att[0][row][col]

    # rzeczywista kolumna wstrzyknięcia błędu - przed ShiftRows
    col += row
    col %= 4

    for key in range(256):
        if (invSBox(key ^ cVal) ^ invSBox(key ^ aVal)) == DFAval:
            return key, row, col


def invKeySchedule(lastKey: list[int], keySize: int) -> str:
    # keySchedule - w przód
    keyNum: int = keySize // 4
    numOfRounds: int = keyNum + 6

    w: list[list[int]] = []  # ???
    for i in range(keyNum):
        w.append([ord(key[4 * i + j]) for j in range(4)])

    def expandKey(word: list[int], round: int) -> list[int]:
        word: list[int] = word[1:] + word[:1]
        for i in range(4):
            row: int = word[i] // 16
            col: int = word[i] % 16
            word[i] = Sbox[row][col]
        word[0] = word[0] ^ RoundConst[round]
        return word

    for i in range(keyNum, 4 * (numOfRounds + 1)):
        if i % keyNum == 0:
            w.append([w[i - keyNum][j] ^ expandKey(w[i - 1], i // keyNum)[j] for j in range(4)])
        else:
            w.append([w[i - keyNum][j] ^ w[i - 1][j] for j in range(4)])

    key_schedule_words = [0] * ((numOfRounds + 1) * keyNum)

    return ''

    # invKeySchedule

# https://crypto.stackexchange.com/questions/31459/aes-inverse-key-schedule

# https://web.archive.org/web/20190629185148/https://github.com/cmcqueen/aes-min/blob/master/aes-min.c#L393
# static void aes128_key_schedule_inv_round(uint8_t p_key[AES128_KEY_SIZE], uint8_t rcon)
# {
#     uint_fast8_t    round;
#     uint8_t       * p_key_0 = p_key + AES128_KEY_SIZE - AES_KEY_SCHEDULE_WORD_SIZE;
#     uint8_t       * p_key_m1 = p_key_0 - AES_KEY_SCHEDULE_WORD_SIZE;
#
#     for (round = 1; round < AES128_KEY_SIZE / AES_KEY_SCHEDULE_WORD_SIZE; ++round)
#     {
#         /* XOR in previous word */
#         p_key_0[0] ^= p_key_m1[0];
#         p_key_0[1] ^= p_key_m1[1];
#         p_key_0[2] ^= p_key_m1[2];
#         p_key_0[3] ^= p_key_m1[3];
#
#         p_key_0 = p_key_m1;
#         p_key_m1 -= AES_KEY_SCHEDULE_WORD_SIZE;
#     }
#
#     /* Rotate previous word and apply S-box. Also XOR Rcon for first byte. */
#     p_key_m1 = p_key + AES128_KEY_SIZE - AES_KEY_SCHEDULE_WORD_SIZE;
#     p_key_0[0] ^= aes_sbox(p_key_m1[1]) ^ rcon;
#     p_key_0[1] ^= aes_sbox(p_key_m1[2]);
#     p_key_0[2] ^= aes_sbox(p_key_m1[3]);
#     p_key_0[3] ^= aes_sbox(p_key_m1[0]);
# }




if __name__ == '__main__':
    # key = keyGen(128)
    key_hex: str = "000102030405060708090a0b0c0d0e0f"
    plaintext_hex: str = "00112233445566778899aabbccddeeff"
    key: str = hex_to_ascii(key_hex)
    plaintext: str = hex_to_ascii(plaintext_hex)
    # print("Klucz ", key.encode('latin1').hex())
    # print("Plaintext :", plaintext.encode('latin1').hex())

    correct: str = encryption(plaintext, key)
    # print("Zaszyfrowany tekst:", correct)

    DFArow: int = randint(0, 3)
    DFAcol: int = randint(0, 3)
    DFAval: int = randint(1, 255)  # to musi być znane

    lastKey: list[int] = []

    for i in range(16):
        DFAval: int = randint(1, 255)  # to musi być znane
        attacked: str = encryptionDFA(plaintext, key, i // 4, i % 4, DFAval)
        # print("Zaszyfrowany tekst:", attacked)

        DFAval, DFArow, DFAcol = recoverRoundKey(correct, attacked, DFAval)
        print(f'Znaleziono bajt klucza: {hex(DFAval)} na pozycji ({DFArow}, {DFAcol})')

        lastKey.append(DFAval)

    print(f'Klucz ostatniej rundy: {[hex(v) for v in lastKey]}')

    # encryptionDFARedundant(plaintext, key, DFArow, DFAcol, DFAval)
