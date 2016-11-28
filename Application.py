from PHPparser import *
from VulnerabilityPattern import *
import sys

# TODO: Remove after debugging
path = "./Slices/"
print path

#files = ["sqli_01_sanitized.txt","sqli_02_sanitized.txt","sqli_03_sanitized.txt","sqli_04_sanitized.txt","sqli_05_sanitized.txt","xss_01_sanitized.txt","xss_02_sanitized.txt","xss_03_sanitized.txt"]#,
        #"teste.txt" ]
#files = ["xss_01.txt", "xss_02.txt", "xss_03.txt"]
#files = ["sqli_05.txt"]
#files = ["sqli_01.txt","sqli_02.txt","sqli_03.txt","sqli_04.txt","sqli_05.txt","xss_01.txt","xss_02.txt","xss_03.txt"]
#files = ["sqli_website.txt"]
#files = ["sqli_01_entry.txt"]
#files = ["teste.txt"]

files = ["sqli_01.txt","sqli_02.txt","sqli_03.txt","sqli_04.txt","sqli_05.txt","xss_01.txt","xss_02.txt","xss_03.txt",
         "sqli_01_sanitized.txt", "sqli_02_sanitized.txt", "sqli_03_sanitized.txt", "sqli_04_sanitized.txt",
         "sqli_05_sanitized.txt", "xss_01_sanitized.txt", "xss_02_sanitized.txt", "xss_03_sanitized.txt",
         "sqli_01_entry.txt", "sqli_website.txt"]


if len(sys.argv) == 1:
    print("Please give the name of the slice file as an argument.")

else:
    filename_patterns = "PatternsFile.txt"
    input = raw_input("Please input the filename of the patterns' file (<enter> for the default option)\n> ").strip()
    if input != "":
        filename_patterns = input

    slices = []
    filename_slices = sys.argv[1]

    try:
        patterns = patterns_from_file(filename_patterns)
        content_file = open(filename_slices, 'r')
        content = content_file.read()

        for pattern in patterns:
            slices.append(Slice(filename_slices, content, pattern))

        for slice in slices:
            if slice.isVulnerable():
                print slice.name + " | this slice is vulnerable: "
                slice.printVulnerabilities()
                print "\n"

    except IOError:
        print("There was an error while opening the file. Please try again.")

"""
slices = []
for file in files:

    # TODO: Remove on final version
    print("\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + file + "#" * 23 + "\n" + "#" * 63 + "\n")

    for pattern in patterns:
        slices.append(Slice(path + file, pattern))

# apenas diz o nome do ficheiro e qual a vulnerabilidade
for slice in slices:
    if slice.isVulnerable():
        print slice.name + " | this slice is vulnerable: "
        slice.printVulnerabilities() #TODO fazer print dentro da funcao ou fora ?
        print "\n"
"""
