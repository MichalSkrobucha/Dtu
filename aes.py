# https://gist.github.com/bonsaiviking/5571001

import sBox

# block[row, col] = list[4 * row + col]


subBox: tuple[chr, ...] = sBox.correctBox


def keySchedule(key: list[chr]) -> list[chr]:
    pass


def subBytes(data: list[chr]) -> list[chr]:
    return [subBox[b] for b in data]


def shiftRows(data: list[chr]) -> list[chr]:
    # [0, 1, 2, ..., 15] -> [0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14]
    pass


def mixColumns(data: list[chr]) -> list[chr]:
    pass


def addRoundKey(data: list[chr], key: list[chr]) -> list[chr]:
    return [chr(ord(d) ^ ord(k)) for d, k in zip(data, key)]


def baseRound(data: list[chr], roundkey: list[chr]) -> list[chr]:
    data = subBytes(data)
    data = shiftRows(data)
    data = mixColumns(data)
    data = addRoundKey(data, roundkey)
    return data


def lastRound(data: list[chr], roundkey: list[chr]) -> list[chr]:
    data = subBytes(data)
    data = shiftRows(data)
    data = addRoundKey(data, roundkey)
    return data


def encryptBlock(data: list[chr], key: list[chr]) -> tuple[list[chr], list[chr]]:
    key = keySchedule(key)

    for _ in range(9):
        data = baseRound(data, key)
        key = keySchedule(key)

    data = lastRound(data, key)
    return data, key
