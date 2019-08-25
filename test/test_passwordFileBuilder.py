import os, sys, inspect
THISDIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
# Add ../lib to the import path
sys.path.insert(0, os.path.dirname(THISDIR) + "/lib")
sys.path.insert(0, os.path.dirname(THISDIR) + "/main")

import fileIO
import passwordFileBuilder

'''
Test functions in passwordFileBuilder.py up to passwords12.txt (if it works up to
that, it is likely to work far past it).

Some sensible assumptions have been made
here regarding scalability - add more tests if you don't think this is sufficient

Delete contents of resOut before running
'''
passwordFileBuilder.THISDIR = THISDIR
passwordFileBuilder.RES = "resOut"
RES = fileIO.genFileName([THISDIR, "resOut/"])

def test_passwordFileBuilder2():
    passwordFileBuilder.RES_IN = "resIn2"
    passwordFileBuilder.passwordFileBuilder()
    assert(sum(1 for line in open(RES + "passwords1.txt")) == 2)



# Again, if this passes, it can be assumed this will be accurate for other values
def test_passwordFileBuilder20():
    passwordFileBuilder.RES_IN = "resIn20"
    passwordFileBuilder.passwordFileBuilder()
    assert(sum(1 for line in open(RES + "passwords1.txt")) == 22)




def test_passwordFileBuilderBoth():
    passwordFileBuilder.RES_IN = "resIn"
    passwordFileBuilder.passwordFileBuilder()
    assert(sum(1 for line in open(RES + "passwords1.txt")) == 44)
