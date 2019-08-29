import os, sys, inspect
THISDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
# Add ../lib to the import path
sys.path.insert(0, os.path.dirname(THISDIR) + "/lib")
sys.path.insert(0, os.path.dirname(THISDIR) + "/main")

import fileIO
import passwordValidator


'''
Test functions in passwordValidator.py
'''

testPwd = "ThisIsaTest1234.,@!"

passwordValidator.THISDIR = THISDIR
passwordValidator.CONFIG = "testConfig.json"

passwordValidator.MIN_LENGTH, passwordValidator.WEAK_SYMBOLS, passwordValidator.WEAK_NUMBERS, passwordValidator.SUGGESTIONS,  passwordValidator.MIN_LENGTH_RES, passwordValidator.MAX_LENGTH_RES, passwordValidator.ENTROPY_THRESHOLD = passwordValidator.readConfig()


def test_readConfig():
    passwordValidator.CONFIG = "testConfig.json"
    minLength, weakSymbols, weakNumbers, suggestions, minLengthRes, maxLengthRes, entropyThreshold = passwordValidator.readConfig()
    assert(minLength == 11)


def test_charInPasswordAll():
    assert(passwordValidator.charInPassword(testPwd, [(chr(0), chr(128))]))


def test_charInPasswordNone():
    assert(not passwordValidator.charInPassword(testPwd, []))


def test_charInPasswordUpper():
    assert(passwordValidator.charInPassword(testPwd, [('A', 'Z')]))


def test_charInPasswordLower():
    assert(passwordValidator.charInPassword(testPwd, [('a', 'z')]))


def test_charInPasswordUpperAndLower():
    assert(passwordValidator.charInPassword(testPwd, [('A', 'Z'), ('a', 'z')]))


def test_charInPasswordNumber():
    assert(passwordValidator.charInPassword(testPwd, [('0', '9')]))


def test_charInPasswordSymbol():
    assert(passwordValidator.charInPassword(testPwd, [('!', '/'), (':', '@'), ('[', '`'), ('{', '~')]))


def test_onlyCharsInPasswordAll():
    error = False
    try:
        passwordValidator.onlyCharsInPassword(testPwd, [(chr(0), chr(128))])
    except:
        error = True
    assert(error)



def test_onlyCharsInPasswordNone():
    assert(not passwordValidator.onlyCharsInPassword(testPwd, []))


'''
The following tests assert false as the testPwd contains additional chars to the
'candidates '
'''
def test_onlyCharsInPasswordUpper():
    assert(not passwordValidator.onlyCharsInPassword(testPwd, [('A', 'Z')]))



def test_onlyCharsInPasswordLower():
    assert(not passwordValidator.onlyCharsInPassword(testPwd, [('a', 'z')]))


def test_onlyCharsInPasswordUpperAndLower():
    assert(not passwordValidator.onlyCharsInPassword(testPwd, [('A', 'Z'), ('a', 'z')]))



def test_onlyCharsInPasswordNumber():
    assert(not passwordValidator.onlyCharsInPassword(testPwd, [('0', '9')]))



def test_onlyCharsInPasswordSymbol():
    assert(not passwordValidator.onlyCharsInPassword(testPwd, [('!', '/'), (':', '@'), ('[', '`'), ('{', '~')]))



def test_passwordValidatorTooShort():
    assert(passwordValidator.passwordValidator("hellothere")[0] == 0)


def test_passwordValidatorLettersOnly():
    assert(passwordValidator.passwordValidator("Hellotherethisisfred")[0] == 1)



def test_passwordValidatorLettersAndNumbers():
    assert(passwordValidator.passwordValidator("Hellotherethisisfred1")[0] == 2)



def test_passwordValidatorCommonNumbers():
    assert(passwordValidator.passwordValidator("Hellotherethisisfred1!")[0] == 3)



def test_passwordValidatorCommonSymbols():
    assert(passwordValidator.passwordValidator("Hellotherethisisfred10!")[0] == 4)


def test_passwordValidatorLowEntropy():
    assert(passwordValidator.passwordValidator("H33~l00th33r33th11s~sfr33d10~")[0] == 5)


def test_passwordValidatorCommonPasswords():
    assert(passwordValidator.passwordValidator("Hellotherethisisfred10~")[0] == 6)


def test_passwordValidatorMax():
    assert(passwordValidator.passwordValidator("gYF22gJM93X84QzRpDOx&rgCpFWYMBYG$g86%rzY04opBjBWYfq46#$47Raxlm39U")[0] == 7)


def test_passwordValidatorCommonNumberAtEnd():
    assert(passwordValidator.passwordValidator("Hellotherethisisfred~1")[0] == 3)

def test_shannonEntropy0():
    assert(int(passwordValidator.shannonEntropy('a')) == 0)

def test_shannonEntropy1():
    assert(int(passwordValidator.shannonEntropy('ab')) == 1)

def test_shannonEntropy2():
    assert(int(passwordValidator.shannonEntropy('abcd')) == 2)

def test_shannonEntropy3():
    assert(int(passwordValidator.shannonEntropy('abcdefgh')) == 3)

def test_shannonEntropy4():
    assert(int(passwordValidator.shannonEntropy('abcdefghijklmnop')) == 4)

def test_shannonEntropy5():
    assert(int(passwordValidator.shannonEntropy('abcdefghijklmnopABCDEFGHIJKLMNOP')) == 5)
