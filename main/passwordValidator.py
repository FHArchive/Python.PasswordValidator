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
import math

CONFIG = "config.json"
RES = "res/"
PASSWORDS = "validatePasswords.txt"

MIN_LENGTH, WEAK_SYMBOLS, WEAK_NUMBERS, SUGGESTIONS, MIN_LENGTH_RES, MAX_LENGTH_RES, ENTROPY_THRESHOLD = "", "", "", "", "", "", 0

def readConfig():
    data = fileIO.readJSON(fileIO.genFileName([THISDIR, CONFIG]))
    return data["minLength"], data["weakSymbols"], data["weakNumbers"], data["suggestions"], data["minLengthRes"], data["maxLengthRes"], data["entropy"]

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
        pos = password.find(str(number))
        adjacentNumber = False
        if pos != -1:
            if (pos + 1) < len(password) and charInPassword(password[pos + 1], [('0', '9')]):
                adjacentNumber = True
            if (pos -1) > -1 and charInPassword(password[pos - 1], [('0', '9')]):
                adjacentNumber = True
            if not adjacentNumber:
                return score, SUGGESTIONS["weakNumbers"], str(number)

    # Common Symbols
    score += 1
    asciiRange = []
    for symbol in WEAK_SYMBOLS:
        asciiRange.append((symbol, symbol))
    if charInPassword(password, asciiRange):
        return score, SUGGESTIONS["weakSymbols"], ""

    # Shannon entropy below threshold
    score += 1
    if shannonEntropy(password) < ENTROPY_THRESHOLD:
        return score, SUGGESTIONS["lowEntropy"], ""

    # Common Passwords in Password
    score += 1
    for length in range(MIN_LENGTH_RES, min(len(password), MAX_LENGTH_RES)):
        commonFileName = fileIO.genFileName([THISDIR, RES, "passwords" + str(length) + ".txt"])
        if os.path.isfile(commonFileName):
            commonFile = open(commonFileName, "r")
            for commonPassword in commonFile:
                if password.lower().find(commonPassword.rstrip().lower()) > -1:
                    return score, SUGGESTIONS["commonPasswordInPassword"], commonPassword[:-1]

    score += 1
    return score, "Max Score", ""

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
Calculates the shannon entropy. Better passwords will have a better
shannon entropy
'''
def shannonEntropy(string):
    probChars = [float(string.count(char)) / len(string) for char in dict.fromkeys(list(string))]
    return - sum([probChar * math.log(probChar) / math.log(2.0) for probChar in probChars])


'''
Global variables are either block caps eg MIN_LENGTH or preceded with g_ eg
g_score
'''
if __name__ == "__main__": # pragma: no cover
    MIN_LENGTH, WEAK_SYMBOLS, WEAK_NUMBERS, SUGGESTIONS, MIN_LENGTH_RES, MAX_LENGTH_RES, ENTROPY_THRESHOLD = readConfig()
    g_passwordTokens = fileIO.fileToTokens(fileIO.genFileName([THISDIR, PASSWORDS]))
    for g_password in g_passwordTokens:
        pskClean = g_password.rstrip()
        g_score, g_suggestion, g_offense = passwordValidator(pskClean)
        print("password:", pskClean)
        print("\tscore:", g_score)
        print("\tsuggestion:", g_suggestion)
        print("\toffense:", g_offense)
