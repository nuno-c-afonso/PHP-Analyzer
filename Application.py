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
