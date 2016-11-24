from PHPparser import *
from VulnerabilityPattern import *
import os

path = os.getcwd() + "/Slices/"
print path

files = ["sqli_01.txt","sqli_02.txt","sqli_03.txt","sqli_04.txt","sqli_05.txt","xss_01.txt","xss_02.txt","xss_03.txt"]#,
        #"teste.txt" ]
#files = ["xss_02.txt"]

filename = raw_input("Please input the filename of the patterns' file (<enter> for the default option)\n> ").strip()
filename = "PatternsFile.txt"
patterns = patterns_from_file(filename)

slices = []
for file in files:
    print("\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + file + "#" * 23 + "\n" + "#" * 63 + "\n")
    for pattern in patterns:

        #TODO: Remove after debugging
        #if pattern.vulnerabilityName == "Cross Site Scripting":
        #    print("\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + pattern.vulnerabilityName + "#" * 23 + "\n" + "#" * 63 + "\n")
        slices.append(Slice(path + file, pattern))

#for slice in slices:
#    slice.process()
# string = re.
