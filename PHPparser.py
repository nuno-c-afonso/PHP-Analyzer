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

        with_parsed_html_php = split_html_php(content)
        lines = split_by_lines(with_parsed_html_php)

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


class PHPatribution:
    def __init__(self, string, identation, vpattern):
        print(identation*"\t" + "atribution: " + string)
        self.identation = identation

        split = string.split("=", 1)
        self.left = PHPvar(split[0].strip(), identation + 1, vpattern)
        self.right = get_rvalue_type(split[1], identation + 1, vpattern)

    def process(self, vars, vpattern):
        integrity = self.right.process(vars, vpattern)
        vars[self.left.string] = integrity
        print(vars)
        return integrity


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


def split_html_php(content):
    html_php = re.findall("<\?.*\?>", content)
    size = len(html_php)
    for i in range(0, size):
        html_php[i] = re.sub("(<\?(php)?)|(\?>)", "", html_php[i])
    without_php_in_html = re.split("<\?.*\?>", content)
    return insert_parsed_php_code(html_php, without_php_in_html)


def insert_parsed_php_code(split_php, without_html_php):
    i = 0
    j = 0
    result = []
    added_original_split = False
    size = len(without_html_php)
    while i < size:
        if (i % 2 != 0) & (not added_original_split):
            result.append(split_php[j])
            j += 1
            added_original_split = True
            continue

        added_original_split = False
        result.append(without_html_php[i])
        i += 1
    return result


def split_by_lines(with_parsed_html_php):
    result = []
    for string in with_parsed_html_php:
        split = string.strip().split("\n")

        for line in split:
            if not(line.startswith("<") | line.endswith(">")):
                result.append(line)
    return result
