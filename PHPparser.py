import re
from VulnerabilityPattern import *


var_regex = "\$[a-zA-Z_]\w*"
php_start_tag_regex = "<\?php\s*"
php_end_tag_regex = "\?>"


class Slice:
    def __init__(self, filePath, vp):
        self.vp = vp

        self.identation = 0
        content_file = open(filePath, 'r')
        content = content_file.read()
        print(" "*61 + "\n" + "-"*23 + " slice content " + "-"*23 + "\n" + " "*61 + "\n" + "\n" + content)

        # TODO: This is only a test. Delete afterwards.
        html = re.findall("<\?.*\?>", content)
        for i in range(0, len(html)):
            html[i] = re.sub("(<\?(php)?)|(\?>)", "", html[i])
            html[i] = html[i].strip()

        without_php_in_html = re.split("<\?.*\?>", content)
        print("PHP CONTENT INSIDE HTML:")
        for string in html:
            print(string)
        print("CONTENT WITHOUT THE PREVIOUS PHP CODE")
        for string in without_php_in_html:
            print(string)

        lines = content.split('\n')
        atributionPatern = re.compile(var_regex + "\s*=\s*.*$")
        atribution_completed = []
        self.slice_order = []
        incomplete = False

        print(" " * 60 + "\n" + "-" * 23 + " parsing tree " + "-" * 23 + "\n" + " " * 60 + "\n")
        for line in lines:
            if incomplete:
                new = atribution_completed[len(atribution_completed) - 1] + " " + line
                atribution_completed[len(atribution_completed) - 1] = new
                if line.endswith(';'):
                    incomplete = False
                    self.slice_order.append(PHPatribution(new, self.identation + 1, self.vp))

            elif atributionPatern.match(line) != None:
                if line.endswith(';'):
                    atribution_completed.append(line)
                    self.slice_order.append(PHPatribution(line, self.identation + 1, self.vp))
                else:
                    incomplete = True
                    atribution_completed.append(line)

            elif line.startswith('<') & line.endswith('>'):
                atribution_completed.append(line)
                self.slice_order.append(HTMLline(line, self.identation + 1, self.vp))

            elif IsSink(line, self.vp):
                atribution_completed.append(line)
                self.slice_order.append(Sink(line, self.identation + 1, self.vp))



        print("\n")
        self.process()
        print("\n")

    def process(self):
        print(" " * 63 + "\n" + "-" * 23 + " tree processing " + "-" * 23 + "\n" + " " * 63 + "\n")
        vars = {}#this is a dictionary
        for e in self.slice_order:
            e.process(vars, self.vp)


def IsSink(line, vpattern):
    for sinkType in vpattern.sensitiveSinks:
        if re.search(sinkType, line) != None:
            return True
    return False


class var:
    def __init__(self, name, integrity):
        self.name = name
        self.integrity = integrity
        print("var: " + name + "integrity: " + integrity)


class PHPatribution:
    def __init__(self, string, identation, vpattern):
        print(identation*"\t" + "atribution: " + string)
        self.identation = identation

        split = string.split("=", 1)
        self.left = PHPvar(split[0], identation + 1, vpattern)
        self.right = get_rvalue_type(split[1], identation + 1, vpattern)

    def process(self, vars, vpattern):
        integrity = self.right.process(vars, vpattern)
        vars[self.left.string] = integrity
        print(vars)
        return integrity


class HTMLline:
    def __init__(self, string, identation, vpattern):
        self.string = string
        self.identation = identation
        self.vars = []

        print(identation * "\t" + "HTMLline: " + string)
        for sink in vpattern.sensitiveSinks:
            if re.search(php_start_tag_regex + sink + "\s*\(?.*\)?.*" + php_end_tag_regex, string) != None:
                groups = re.findall(php_start_tag_regex + sink + "\s*\(?.*\)?.*" + php_end_tag_regex, string)
                for cut in groups:
                    var = re.search(php_start_tag_regex + sink + "\s*\(?.*\)?.*" + php_end_tag_regex, cut).groups()
                    if len(var) > 0:
                        self.vars.append(PHPvar(var[0], identation + 1, vpattern))

    def process(self, vars, vpattern):
        for var in self.vars:
            if vars.get(var.string) != None:
                if vars.get(var.string) == "low":
                    print("X--> XSS in " + self.string + " because of " + var.string)
                    return "low"
        return "high"


class Sink:
    def __init__(self, string, identation, vpattern):
        self.identation = identation
        self.string = string.strip(";").strip()
        self.vars = []
        self.entries = []
        print(self.identation * "\t" + "Sink: " + self.string)

        for sinkType in vpattern.sensitiveSinks:
            if self.string.startswith(sinkType):
                self.string = self.string.lstrip(sinkType)
                break

        self.vars = get_entries_in_sink(self.string, identation+1, vpattern)


    def process(self, vars, vpattern):
        integrity = "high"
        for var in self.vars:
            if var.process(vars, vpattern) == "low":
                print("X-->" + vpattern.vulnerabilityName + " in " + self.string + " because of " + var.string)
                integrity = "low"

        return integrity


class PhpStrings:
    def __init__(self, string, identation, vpattern):
        self.identation = identation
        self.string = string
        self.vars = []
        print(identation * "\t" + "PhpStrings: " + string)

        groups = re.findall("\s*\'" + var_regex + "\'\s*", string)
        for cut in groups:
            cut = re.sub("\'", "", cut)
            self.vars.append(PHPvar(cut, identation + 1, vpattern))

    def process(self, vars, vpattern):
        for var in self.vars:
            if vars.get(var.string) == "low":
                return "low"
        return "high"


class Sanitization:
    def __init__(self, string, identation, vpattern):
        self.identation = identation
        self.string = string
        self.vars = []
        print(identation * "\t" + "Sanitization: " + string)

        groups = re.findall(var_regex, string)
        for cut in groups:
            self.vars.append(PHPvar(cut, identation + 1, vpattern))

    def process(self, vars, vpattern):
        return "high"


class PHPentry:
    def __init__(self, string,identation,vpattern):
        self.string = string
        print(identation * "\t" + "PHPentry: " + string)

    def process(self, vars, vpattern):
        return "low"


class PHPvar:
    def __init__(self, string, identation,vpattern):
        self.string = string
        print(identation * "\t" + "PHPvar: " + string)

    # TODO: Confirm if a variable can be outside the list (it has None in the vars list)
    def process(self, vars, vpattern):
        if vars.get(self.string) != None:
            return vars.get(self.string)
        return "low"


class UnknownRValue:
    def __init__(self, string, identation, vpattern):
        self.string = string
        print(identation * "\t" + "UnknownRValue: " + string)

    # TODO: Confirm if this should always return high integrity level
    def process(self, vars, vpattern):
        return "high"


def get_rvalue_type(string, identation, vpattern):
    str = string.strip()

    if str.startswith('\"') & str.endswith('\";'):
        return PhpStrings(str, identation, vpattern)

    # TODO: The specific types may not be at the start of the string. Maybe they are concatenated.
    for entryType in vpattern.entryPoints:
        if str.startswith(entryType):
            return PHPentry(str, identation, vpattern)

    for sanitize_type in vpattern.sanitizationFunctions:
        if str.startswith(sanitize_type):
            return Sanitization(str, identation, vpattern)

    for sinkType in vpattern.sensitiveSinks:
        if re.search(sinkType, str) != None:
            return Sink(str, identation, vpattern)

    if str.startswith("$"):
        return PHPvar(str, identation, vpattern)

    return UnknownRValue(str, identation, vpattern)


def get_vars(string, identation, vpattern):
    str = string.strip()

    if str.startswith('\"') & str.endswith('\";'):
        return PhpStrings(str, identation, vpattern)

    # TODO: The specific types may not be at the start of the string. Maybe they are concatenated.
    for entryType in vpattern.entryPoints:
        if str.search(entryType):
            return PHPentry(str, identation, vpattern)

    for sanitize_type in vpattern.sanitizationFunctions:
        if str.startswith(sanitize_type):
            return Sanitization(str, identation, vpattern)

    for sinkType in vpattern.sensitiveSinks:
        if re.search(sinkType, str) != None:
            return Sink(str, identation, vpattern)

    if str.startswith("$"):
        return PHPvar(str, identation, vpattern)


def get_entries_in_sink(string, identation, vpattern):
    #print("get_entries_in_sink "+ string)
    striped = string.strip(" ")
    striped = striped.lstrip("(").rstrip(")")
    striped = striped.strip(" ")

    var_lines = striped.split(",")
    vars = []

    for line in var_lines:
        mach = False
        #print("line: "+line)
        str = line.strip()
        if str.startswith('\"') & str.endswith('\";'):
            vars.append(PhpStrings(str, identation, vpattern))

        elif mach != True:
            for entryType in vpattern.entryPoints:
                if str.startswith(entryType):
                    vars.append(PHPentry(str, identation, vpattern))
                    mach = True
        elif mach != True:
            for sanitize_type in vpattern.sanitizationFunctions:
                if str.startswith(sanitize_type):
                    vars.append(Sanitization(str, identation, vpattern))
                    mach = True
        elif mach != True:
            for sinkType in vpattern.sensitiveSinks:
                if str.startswith(sinkType) != None:
                    vars.append(Sink(str, identation, vpattern))
                    mach = True

        if mach != True & str.startswith("$"):
            vars.append(PHPvar(str, identation, vpattern))

    return vars








from PHPparser import *
from VulnerabilityPattern import *
import os


path = os.getcwd() + "/Slices/"
print(path)

files = ["sqli_01.txt","sqli_02.txt","sqli_03.txt","sqli_04.txt","sqli_05.txt","xss_01.txt","xss_02.txt","xss_03.txt"]#,
        #"teste.txt" ]
#files = ["xss_01.txt", "xss_02.txt", "xss_03.txt"]
#files = ["xss_02.txt"]

#filename = raw_input("Please input the filename of the patterns' file (<enter> for the default option)\n> ").strip()
filename = "PatternsFile.txt"
filename = "PatternsTest.txt"
patterns = patterns_from_file(filename)

slices = []
for file in files:
    print("\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + file + "#" * 23 + "\n" + "#" * 63 + "\n")
    for pattern in patterns:

        #TODO: Remove after debugging
        #if pattern.vulnerabilityName == "Cross Site Scripting":
        print("\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + pattern.vulnerabilityName + "#" * 23 + "\n" + "#" * 63 + "\n")
        slices.append(Slice(path + file, pattern))