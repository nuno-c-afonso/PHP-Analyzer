from PHPparser import *
from VulnerabilityPattern import *
from OutputColors import *
import sys


if len(sys.argv) == 1:
    print(colors.RED+"Please give the name of the slice file as an argument."+colors.RESET)

else:
    filename_patterns = "PatternsFile.txt"
    input = raw_input("Please input the filename of the patterns' file (<enter> for the default option)\n> ").strip()
    print("\n")

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

        prev_slice_name = ""

        if not debugging:
            for slice in slices:
                if prev_slice_name != slice.name:
                    prev_slice_name = slice.name
                    print("\n\n")
                    print(colors.BLUE + "#" * 83 + colors.RESET)
                    print(colors.BLUE + "#" * 2 + colors.RESET + slice.name.center(79,
                                                                                   ' ') + colors.BLUE + "#" * 2 + colors.RESET)
                    print(colors.BLUE + "#" * 83 + colors.RESET)

                print("#" * 83)
                print("#" * 2 + slice.vp.vulnerabilityName.center(79, ' ') + "#" * 2)
                print("#" * 83)
                if slice.isVulnerable():
                    slice.printVulnerabilities()
                slice.printAllVulnInfo()
                print("\n" + colors.YELLOW + "#" * 30 + "Integrity Flow".center(23, ' ') + "#" * 30 + colors.RESET)
                print(getGraphCaption())
                tree = slice.getVulnTreeInfo()
                for treeline in tree:
                    print(treeline)
                print("\n\n")

    except IOError:
        print("There was an error while opening the file. Please try again.")


# TODO: Remove after debugging
"""
path = "./Slices/"

files = ["sqli_01.txt","sqli_02.txt","sqli_03.txt","sqli_04.txt","sqli_05.txt","xss_01.txt","xss_02.txt","xss_03.txt",
         "sqli_01_sanitized.txt", "sqli_02_sanitized.txt", "sqli_03_sanitized.txt", "sqli_04_sanitized.txt",
         "sqli_05_sanitized.txt", "xss_01_sanitized.txt", "xss_02_sanitized.txt", "xss_03_sanitized.txt",
         "sqli_01_entry.txt", "sqli_website.txt", "teste.txt","sqli_unknown_rvalue.txt"]

#filename_patterns = "PatternsFile.txt"
filename_patterns = "PatternsTest.txt"
slices = []
filename_slices = "Slices/sqli_04_sanitized.txt"
try:
    patterns = patterns_from_file(filename_patterns)

    for file in files:
        if debugging:
            print(colors.BLUE + "#" * 83 + "\n"  + "#" * 2 + file.center(79, ' ') + "#" * 2 + "\n"+ "#" * 83 + colors.RESET)
        content_file = open(path+file, 'r')
        content = content_file.read()
        for pattern in patterns:
            slices.append(Slice(path+file, content, pattern))

    prev_slice_name = ""
    for slice in slices:
        if prev_slice_name != slice.name:
            prev_slice_name = slice.name
            if not debugging:
                print("\n\n")
                print(colors.BLUE + "#" * 83 + colors.RESET)
                print(colors.BLUE + "#" * 2 + colors.RESET + slice.name.center(79, ' ') + colors.BLUE + "#" * 2 + colors.RESET)
                print(colors.BLUE + "#" * 83 + colors.RESET)

        if not debugging:
            print("#" * 83)
            print("#" * 2 + slice.vp.vulnerabilityName.center(79, ' ') + "#" * 2)
            print("#" * 83)

        if not debugging:
            if slice.isVulnerable():
                slice.printVulnerabilities()
            slice.printAllVulnInfo()


        if not debugging:
            print("\n" +colors.YELLOW +"#"*30 + "Integrity Flow".center(23, ' ') + "#"*30 + colors.RESET )
            print(getGraphCaption())
        tree = slice.getVulnTreeInfo()
        for treeline in tree:
            if not debugging:
                print(treeline)
        if not debugging:
            print("\n\n")


except IOError:
    print("There was an error while opening the file. Please try again.")
"""


