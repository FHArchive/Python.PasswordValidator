'''
Author FredHappyface
Date 2019/07/22

passwordFileBuilder.py takes a set of common passwords and sorts them into
files of their length
'''
import os, sys, inspect
THISDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
# Add ../lib to the import path
sys.path.insert(0, os.path.dirname(THISDIR) + "/lib")

import fileIO

RES_IN = "resIn/"
RES = "res/"

def passwordFileBuilder():
    for inFileName in fileIO.getListOfFiles(fileIO.genFileName([THISDIR, RES_IN]), False):
        inFile = open(inFileName, "r")
        for password in inFile:
            outFile = open(fileIO.genFileName([THISDIR, RES, "passwords" + str(len(password)-1) + ".txt"]), "a+")
            outFile.write(password)

if __name__ == "__main__": # pragma: no cover
    passwordFileBuilder()
