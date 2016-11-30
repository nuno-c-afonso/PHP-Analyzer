import re
from VulnerabilityPattern import *
from OutputColors import *


var_regex = "\$[a-zA-Z_]\w*"
php_start_tag_regex = "<\?php\s*"
php_end_tag_regex = "\?>"
debugging = True

def getPHPLines(content):
    d = ";"
    return [line + d for line in content.split(d) if line != ""]

class Slice:
    def __init__(self, filePath, content, vp):
        self.vp = vp
        self.name = filePath
        self.identation = 0
        self.treeLog = []

        if debugging:
            print(colors.YELLOW+"\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + vp.vulnerabilityName + "#" * 23 + "\n" + "#" * 63 + "\n"+colors.RESET)
            print(" "*61 + "\n" + "-"*23 + " slice content " + "-"*23 + "\n" + " "*61 + "\n" + "\n" + content)

        content = sub_html_php(content)
        lines = getPHPLines(content.replace('\n', '').replace('\r', ''))

        atributionPatern = re.compile(var_regex + "\s*=\s*.*$")
        self.slice_order = []

        if debugging:
            print(" " * 60 + "\n" + "-" * 23 + " parsing tree " + "-" * 23 + "\n" + " " * 60 + "\n")

        for line in lines:
            if atributionPatern.match(line) != None:
                self.slice_order.append(PHPatribution(line, self.identation + 1, self.vp))

            elif IsSink(line, self.vp):
                createdSink = Sink(line, self.identation + 1, self.vp)
                self.slice_order.append(createdSink)

        self.process()


    def process(self):
        order = []
        if debugging:
            print(" " * 63 + "\n" + "-" * 23 + " tree processing " + "-" * 23 + "\n" + " " * 63 + "\n")
            print(getGraphCaption())
        vars = {}#this is a dictionary
        for e in self.slice_order:
            e.process(vars, self.vp, order)

        color_line = getVarsIntegrityLine(vars, order)
        self.treeLog.append(color_line)
        if debugging:
           print(color_line)

    def isVulnerable(self):
        for sink_or_attr in self.slice_order:
            if sink_or_attr.isVulnerable():
                return True
        return False

    def printVulnerabilities(self):
        for sink_or_attr in self.slice_order:
            sink_or_attr.printVulnerabilities()

    def printAllVulnInfo(self):
        for sink_or_attr in self.slice_order:
            sink_or_attr.printAllVulnInfo()

    def getVulnTreeInfo(self):
        strings = []
        for sink_or_attr in self.slice_order:
            strings.extend(sink_or_attr.getVulnTreeInfo())
        strings.extend(self.treeLog[:])
        return strings



def IsSink(line, vpattern):
    for sinkType in vpattern.sensitiveSinks:
        if re.search(sinkType, line) != None:
            return True
    return False


class PHPatribution:
    def __init__(self, string, identation, vpattern):
        if debugging:
            print(identation*"\t" + "atribution: " + string)
        self.identation = identation
        self.treeLog = []

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

    def printAllVulnInfo(self):
        if isinstance(self.right, Sink):
            return self.right.printAllVulnInfo()

    def getVulnTreeInfo(self):
        strings = self.treeLog[:]
        if isinstance(self.right, Sink):
            strings.extend(self.right.getVulnTreeInfo())
        return strings



    def process(self, vars, vpattern, order):
        color_line = getVarsIntegrityLine(vars,order)
        self.treeLog.append(color_line)
        if debugging:
            print(color_line)


        integrity = self.right.process(vars, vpattern, order)

        if self.left.string not in order:
            order.append(self.left.string)

        color_line = getTransformationLine(self.right, order, self.left.string, vars)
        self.treeLog.append(color_line)
        if debugging:
            #print(getVarsIntegrityLine(vars, order))
            print(color_line)

        vars[self.left.string] = integrity

        return integrity


class Sink:
    def __init__(self, string, identation, vpattern):

        self.processed = False

        self.treeLog = []

        self.vulnCleanList = []
        self.vulnList = []
        self.vulnerableState = -1

        self.identation = identation
        self.string = string.strip(";").strip()
        self.instructionLine = self.string
        self.vars = []
        self.entries = []
        auxString = ""
        if debugging:
            print(self.identation * "\t" + "Sink: " + self.string)

        for sinkType in vpattern.sensitiveSinks:
            if self.string.startswith(sinkType):
                auxString = self.string.lstrip(sinkType)
                break

        self.vars = get_entries_in_sink(auxString, identation + 1, vpattern)

    def isVulnerable(self):
        return self.processed == True and self.vulnerableState == 1

    def printVulnerabilities(self):
        for vuln in self.vulnList:
            print("X-->" + vuln[0].vulnerabilityName + " in: " + vuln[1] + "\n\tbecause of: " + vuln[2])

    def printAllVulnInfo(self):
        for info in self.vulnCleanList:
            print(info)

    def getVulnTreeInfo(self):
        return self.treeLog

    def process(self, vars, vpattern, order):
        self.vulnerableState = 0

        integrity = "high"
        for var in self.vars:
            if var.process(vars, vpattern, order) == "low":
                varVulnPrint = getSinkPrintVuln(vpattern.vulnerabilityName, self.instructionLine, var.string, vars, order)
                self.treeLog.append(varVulnPrint)
                if debugging:
                    print(varVulnPrint)

                integrity = "low"
                self.vulnerableState = 1
                self.vulnList.append([vpattern, self.instructionLine, var.string])

        if integrity =="high":
            varCleanPrint = getSinkPrintClean(vpattern.vulnerabilityName,self.instructionLine, vars,order)
            self.treeLog.append(varCleanPrint)

            justInjectionText = varCleanPrint.split("|")[-1].strip()
            self.vulnCleanList.append(justInjectionText)
            if debugging:
                print(varCleanPrint)

        self.processed = True
        return integrity


class PhpStrings:
    def __init__(self, string, identation, vpattern):
        self.identation = identation
        self.string = string
        self.vars = []
        if debugging:
            print(identation * "\t" + "PhpStrings: " + string)

        groups = re.findall("\'\s*[a-zA-Z0-9_\$\"\(\)\[\], ]+\s*\'", string)
        groups_with_quotes = re.findall("\"\s*\.\s*[a-zA-Z0-9_\$\'\(\)\[\], ]+\s*\.\s*\"", string)
        for cut in groups:
            cut = cut.strip("\'").strip()
            entry = get_entry(cut, identation + 1, vpattern)
            if entry:
                self.vars.append(entry)

        for cut in groups_with_quotes:
            cut = cut.strip("\"").strip().strip(".").strip()
            entry = get_entry(cut, identation + 1, vpattern)
            if entry:
                self.vars.append(entry)

    def process(self, vars, vpattern, order):
        for var in self.vars:
            if var.process(vars, vpattern, order) == "low":
                return "low"
        return "high"


class Sanitization:
    def __init__(self, string, identation, vpattern):
        self.identation = identation
        self.string = string
        if debugging:
            print(identation * "\t" + "Sanitization: " + string)

    def process(self, vars, vpattern, order):
        return "high"


class PHPentry:
    def __init__(self, string,identation, vpattern):
        self.string = string
        if debugging:
            print(identation * "\t" + "PHPentry: " + string)

    def process(self, vars, vpattern, order):
        return "low"


class PHPvar:
    def __init__(self, string, identation,vpattern):
        self.string = string
        if debugging:
            print(identation * "\t" + "PHPvar: " + string)

    def process(self, vars, vpattern, order):
        if vars.get(self.string) != None:
            return vars.get(self.string)
        return "high"


class UnknownRValue:
    def __init__(self, string, identation, vpattern):
        self.string = string
        self.vars = []
        if debugging:
            print(identation * "\t" + "UnknownRValue: " + string)

        string = string.strip()
        i=0
        if string.count("(")!=0:
            i=string.index("(")

        if string.count(" ") != 0:
            i = min([i, string.index(" ")])

        if i!=0:
            inputs = string[i:]
            self.vars = get_entries_in_sink(inputs, identation + 1, vpattern)



    def process(self, vars, vpattern, order):
        for var in self.vars:
            if var.process(vars, vpattern, order) == "low":
                return "low"
        return "high"


def get_rvalue_type(string, identation, vpattern):
    str = string.strip().strip(";").strip()

    if str.startswith('\"') and str.endswith('\"'):
        return PhpStrings(str, identation, vpattern)

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


def get_entries_in_sink(string, identation, vpattern):
    striped = string.strip(" ")
    striped = striped.lstrip("(").rstrip(")")
    striped = striped.strip(" ")

    var_lines = remove_outer_commas(striped)
    vars = []

    for line in var_lines:
        str = line.strip()

        if str.startswith('\"') and str.endswith('\"'):
            vars.append(PhpStrings(str, identation, vpattern))

        else:
            entry = get_entry(str, identation, vpattern)
            if entry:
                vars.append(entry)

    return vars


def get_entry(str, identation, vpattern):
    for sanitize_type in vpattern.sanitizationFunctions:
        if str.startswith(sanitize_type):
            return Sanitization(str, identation, vpattern)

    for sinkType in vpattern.sensitiveSinks:
        if str.startswith(sinkType):
            return Sink(str, identation, vpattern)

    for entryType in vpattern.entryPoints:
        if str.startswith(entryType):
            return PHPentry(str, identation, vpattern)

    if str.startswith("$"):
        return PHPvar(str, identation, vpattern)

    return None


def sub_html_php(content):
    content_inicial = content

    html_php = re.search("<\?.*\?>", content)
    while html_php:
        html_php = html_php.group()
        html_php = re.sub("(<\?([Pp][Hh][Pp])?)|(\?>)", "", html_php).strip()
        if not html_php.endswith(";"):
            html_php += ";"

        content = re.sub("<.*>", html_php, content, 1)
        html_php = re.search("<\?.*\?>", content)

    if debugging:
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
        if not (line.startswith("<") or line.endswith(">")):
            result.append(line)

    return result


def remove_outer_commas(string):
    string_prime = False
    string_quote = False
    inside_parenthesis = 0
    result = []
    current_string = ""

    for char in string:
        if char == "," and not (string_prime or string_quote) and inside_parenthesis == 0:
            result.append(current_string)
            current_string = ""

        else:
            if char == "\"":
                if inside_parenthesis == 0 and not string_prime:
                    string_quote = not string_quote

            elif char == "'":
                if inside_parenthesis == 0 and not string_quote:
                    string_prime = not string_prime

            elif char == "(":
                if not(string_prime or string_quote):
                    inside_parenthesis += 1

            elif char == ")":
                if not(string_prime or string_quote):
                    inside_parenthesis -= 1

            current_string += char

    if len(current_string) != 0:
        result.append(current_string)

    return result
