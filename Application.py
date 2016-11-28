from PHPparser import *
from VulnerabilityPattern import *
import os
import sys

# TODO: Remove after debugging
path = "./Slices/"
print path

#files = ["sqli_01_sanitized.txt","sqli_02_sanitized.txt","sqli_03_sanitized.txt","sqli_04_sanitized.txt","sqli_05_sanitized.txt","xss_01_sanitized.txt","xss_02_sanitized.txt","xss_03_sanitized.txt"]#,
        #"teste.txt" ]
#files = ["xss_01.txt", "xss_02.txt", "xss_03.txt"]
#files = ["xss_02.txt"]
files = ["sqli_01.txt","sqli_02.txt","sqli_03.txt","sqli_04.txt","sqli_05.txt","xss_01.txt","xss_02.txt","xss_03.txt"]
#files = ["sqli_website.txt"]
#files = ["sqli_01_entry.txt"]

#filename = raw_input("Please input the filename of the patterns' file (<enter> for the default option)\n> ").strip()
#filename = "PatternsFile.txt"
filename = "PatternsTest.txt"
patterns = patterns_from_file(filename)

# FIXME: This should exist in the final version of the project (it is asked for in the course web page)
"""
if len(sys.argv) == 1:
    print("Please give the name of the slice file as an argument.")

else:
    slice = sys.argv[1]
    for pattern in patterns:
        # TODO: Remove after debugging
        print("\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + pattern.vulnerabilityName + "#" * 23 + "\n" + "#" * 63 + "\n")
        Slice(slice, pattern)
"""
slices = []
for file in files:
    print("\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + file + "#" * 23 + "\n" + "#" * 63 + "\n")

    for pattern in patterns:
        #TODO: Remove after debugging
        print("\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + pattern.vulnerabilityName + "#" * 23 + "\n" + "#" * 63 + "\n")
        slices.append(Slice(path + file, pattern))



#FIXME TODO dizer tambem qual o vpattern ao certo que a detectou ?
# apenas diz o nome do ficheiro e qual a vulnerabilidade
for slice in slices:
    if slice.isVulnerable():
        print slice.name + " | this slice is vulnerable: "
        slice.printVulnerabilities() #TODO fazer print dentro da funcao ou fora ?
        print "\n"

