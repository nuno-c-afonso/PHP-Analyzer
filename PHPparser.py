import re
from VulnerabilityPattern import *


var_regex = "\$[a-zA-Z_]\w*"
php_start_tag_regex = "<\?php\s*"
php_end_tag_regex = "\?>"

def getPHPLines(content):
    d = ";"
    return [line + d for line in content.split(d) if line != ""]

class Slice:
    def __init__(self, filePath, vp):
        self.vp = vp
        self.name = filePath

        self.identation = 0
        content_file = open(filePath, 'r')
        content = content_file.read()
        print(" "*61 + "\n" + "-"*23 + " slice content " + "-"*23 + "\n" + " "*61 + "\n" + "\n" + content)

        content = sub_html_php(content)
        lines = getPHPLines(content.replace('\n', '').replace('\r', ''))

        atributionPatern = re.compile(var_regex + "\s*=\s*.*$")
        self.slice_order = []

        print(" " * 60 + "\n" + "-" * 23 + " parsing tree " + "-" * 23 + "\n" + " " * 60 + "\n")

        for line in lines:
            if atributionPatern.match(line) != None:
                self.slice_order.append(PHPatribution(line, self.identation + 1, self.vp))

            elif IsSink(line, self.vp):
                createdSink = Sink(line, self.identation + 1, self.vp)
                self.slice_order.append(createdSink)

        print("\n")
        self.process()
        print("\n")

    def process(self):
        print(" " * 63 + "\n" + "-" * 23 + " tree processing " + "-" * 23 + "\n" + " " * 63 + "\n")
        vars = {}#this is a dictionary
        for e in self.slice_order:
            e.process(vars, self.vp)

    def isVulnerable(self):
        for sink_or_attr in self.slice_order:
            if sink_or_attr.isVulnerable():
                return True
        return False

    def printVulnerabilities(self):
        for sink_or_attr in self.slice_order:
            sink_or_attr.printVulnerabilities()



def IsSink(line, vpattern):
    for sinkType in vpattern.sensitiveSinks:
        if re.search(sinkType, line) != None:
            return True
    return False


class PHPatribution:
    def __init__(self, string, identation, vpattern):
        print(identation*"\t" + "atribution: " + string)
        self.identation = identation

        string = string.strip(";").strip()
        split = string.split("=", 1)
        self.left = PHPvar(split[0].strip(), identation + 1, vpattern)
        self.right = get_rvalue_type(split[1], identation + 1, vpattern)

    def isVulnerable(self):
        if isinstance(self.right, Sink):
            return self.right.isVulnerable()

    def printVulnerabilities(self):
        if isinstance(self.right, Sink):
            return self.right.printVulnerabilities()

    def process(self, vars, vpattern):
        integrity = self.right.process(vars, vpattern)
        vars[self.left.string] = integrity
        print(vars)
        return integrity


class Sink:
    def __init__(self, string, identation, vpattern):

        self.processed = False
        self.vulnList = []
        self.vulnerableState = -1;

        self.identation = identation
        self.string = string.strip(";").strip()
        self.instructionLine = self.string
        self.vars = []
        self.entries = []
        print(self.identation * "\t" + "Sink: " + self.string)

        for sinkType in vpattern.sensitiveSinks:
            if self.string.startswith(sinkType):
                self.string = self.string.lstrip(sinkType)
                break

        self.vars = get_entries_in_sink(self.string, identation + 1, vpattern)

    def isVulnerable(self):
        return self.processed == True and self.vulnerableState == 1

    def printVulnerabilities(self):
        for vuln in self.vulnList:
            # print("X-->" + vpattern.vulnerabilityName + " in: " + self.instructionLine + "\n\tbecause of: " + var.string)
            print("X-->" + vuln[0].vulnerabilityName + " in: " + vuln[1] + "\n\tbecause of: " + vuln[2])

    def process(self, vars, vpattern):
        self.vulnerableState = 0

        integrity = "high"
        for var in self.vars:
            if var.process(vars, vpattern) == "low":
                print("X-->" + vpattern.vulnerabilityName + " in: " + self.instructionLine + "\n\tbecause of: " + var.string)
                integrity = "low"
                self.vulnerableState = 1
                self.vulnList.append([vpattern, self.instructionLine, var.string])

        self.processed = True
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
        return "high"


class UnknownRValue:
    def __init__(self, string, identation, vpattern):
        self.string = string
        print(identation * "\t" + "UnknownRValue: " + string)

    # TODO: Confirm if this should always return high integrity level
    def process(self, vars, vpattern):
        return "high"


def get_rvalue_type(string, identation, vpattern):
    str = string.strip().strip(";").strip()

    if str.startswith('\"') & str.endswith('\"'):
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

"""
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
"""

def get_entries_in_sink(string, identation, vpattern):
    #print("get_entries_in_sink "+ string)
    striped = string.strip(" ")
    striped = striped.lstrip("(").rstrip(")")
    striped = striped.strip(" ")

    var_lines = striped.split(",")
    vars = []

    for line in var_lines:
        mach = False
        # print("line: "+line)
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


def sub_html_php(content):
    content_inicial = content
    #print("INITIAL CONTENT:")
    #print(content)

    html_php = re.search("<\?.*\?>", content)
    while html_php:
        html_php = html_php.group()
        html_php = re.sub("(<\?([Pp][Hh][Pp])?)|(\?>)", "", html_php).strip()
        if not html_php.endswith(";"):
            html_php += ";"

        content = re.sub("<.*>", html_php, content, 1)
        html_php = re.search("<\?.*\?>", content)

    #print("END CONTENT:")
    #print(content)
    if content_inicial != content:
        print("INITIAL CONTENT:")
        print(content_inicial)

        print("END CONTENT:")
        print(content)
    else:
        print("sub_html_php: did nothing")

    return content


def split_by_lines(content):
    result = []
    lines = content.split("\n")
    for line in lines:
        line = line.strip()
        if not (line.startswith("<") | line.endswith(">")):
            result.append(line)

    return result
