'''
Author FredHappyface
Date 2019/07/22

passwordValidator.py is a more intelligent password validator that fails early
and suggests changes to your passwords
'''
import os, sys, inspect
THISDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
# Add ../lib to the import path
sys.path.insert(0, os.path.dirname(THISDIR) + "/lib")

import fileIO

CONFIG = "config.json"
RES = "res/"
PASSWORDS = "validatePasswords.txt"

MIN_LENGTH, WEAK_SYMBOLS, WEAK_NUMBERS, SUGGESTIONS, MAX_SCORE = "", "", "", "", ""

def readConfig():
    data = fileIO.readJSON(fileIO.genFileName([THISDIR, CONFIG]))
    return data["minLength"], data["weakSymbols"], data["weakNumbers"], data["suggestions"], data["maxScore"], data["minLengthRes"], data["maxLengthRes"]

def passwordValidator(password):
    score = 0
    # Too Short
    if len(password) < MIN_LENGTH:
        return score, SUGGESTIONS["underMinLength"], str(len(password))
    # Letters Only
    score += 1

    if onlyCharsInPassword(password, [('A', 'Z'), ('a', 'z')]):
        return score, SUGGESTIONS["lettersOnly"], ""

    # Letters and Numbers Only
    score += 1
    if onlyCharsInPassword(password, [('0', '9'), ('A', 'Z'), ('a', 'z')]):
        return score, SUGGESTIONS["lettersAndNumbersOnly"], ""

    # Common Numbers
    score += 1
    for number in WEAK_NUMBERS:
        nextPos = password.find(str(number)) + 1
        if nextPos >= len(password):
            return score, SUGGESTIONS["weakNumbers"], str(number)
        if nextPos != 0:
            if charInPassword(password[nextPos], [('!', '/'), (':', '@'), ('A', 'Z'), ('[', '`'), ('a', 'z'), ('{', '~')]):
                return score, SUGGESTIONS["weakNumbers"], str(number)


    # Common Symbols
    score += 1
    asciiRange = []
    for symbol in WEAK_SYMBOLS:
        asciiRange.append((symbol, symbol))
    if charInPassword(password, asciiRange):
        return score, SUGGESTIONS["weakSymbols"], ""

    # Common Passwords in Password
    score += 1
    for length in range(MIN_LENGTH_RES, min(len(password), MAX_LENGTH_RES)):
        commonFileName = fileIO.genFileName([THISDIR, RES, "passwords" + str(length) + ".txt"])
        if os.path.isfile(commonFileName):
            commonFile = open(commonFileName, "r")
            for commonPassword in commonFile:
                if password.lower().find(commonPassword.rstrip().lower()) > -1:
                    return score, SUGGESTIONS["commonPasswordInPassword"], commonPassword[:-1]

    return MAX_SCORE, "Max Score", ""

def charInPassword(password, asciiRange):
    for char in password:
        for asciiChars in asciiRange:
            if ord(char) >= ord(asciiChars[0]) and ord(char) <= ord(asciiChars[1]):
                return True
    return False

def onlyCharsInPassword(password, asciiRange):
    pointer = 0
    notAsciiRange = []
    for asciiChars in asciiRange:
        notAsciiRange.append((chr(pointer), chr(ord(asciiChars[0]) -1)))
        pointer = ord(asciiChars[1]) + 1
    notAsciiRange.append((chr(pointer), chr(128)))
    return not charInPassword(password, notAsciiRange)


'''
Global variables are either block caps eg MIN_LENGTH or preceded with g_ eg
g_score
'''
if __name__ == "__main__": # pragma: no cover
    MIN_LENGTH, WEAK_SYMBOLS, WEAK_NUMBERS, SUGGESTIONS, MAX_SCORE, MIN_LENGTH_RES, MAX_LENGTH_RES = readConfig()
    g_passwordTokens = fileIO.fileToTokens(fileIO.genFileName([THISDIR, PASSWORDS]))
    for g_password in g_passwordTokens:
        pskClean = g_password.rstrip()
        g_score, g_suggestion, g_offense = passwordValidator(pskClean)
        print("password:", pskClean)
        print("\tscore:", g_score)
        print("\tsuggestion:", g_suggestion)
        print("\toffense:", g_offense)
