import re
import os
from phply import *

global SQLIsinks
SQLIsinks=("mysql_query\((.*?)\)",
             "mysql_unbuffered_query\((.*?)\)",
             "mysql_db_query\((.*?)\)",
             "mysqli_query\((.*?)\)",
             "mysqli_real_query\((.*?)\)",
             "mysqli_master_query\((.*?)\)",
             "mysqli_multi_query\((.*?)\)",
             "mysqli_stmt_execute\((.*?)\)",
             "mysqli_execute\((.*?)\)",
             "mysqli::query\((.*?)\)",
             "mysqli::multi_query\((.*?)\)",
             "mysqli::real_query\((.*?)\)",
           "mysqli_stmt::execute\((.*?)\)",
           "db2_exec\((.*?)\)",
           "pg_query\((.*?)\)",
           "pg_send_query\((.*?)\)")
global XSSsinks
XSSsinks = ("echo",
            "print",
            "printf",
            "die",
            "error",
            "exit",
            "file_put_contents",
            "file_get_contents",)


global SQLIentrys
SQLIentrys = ("$_GET",
            "$_POST",
            "$_COOKIE",
            "$_REQUEST",
            "HTTP_GET_VARS",
            "HTTP_POST_VARS",
            "HTTP_COOKIE_VARS",
            "HTTP_REQUEST_VARS",)


global MySQLSanitization
MySQLSanitization=("mysql_escape_string(%s)",
                "mysql_real_escape_string(%s)",
                "mysqli_escape_string(%s)",
                "mysqli_real_escape_string(%s)",
                "mysqli_stmt_bind_param(%s)",
                "mysqli::escape_string(%s)",
                "mysqli::real_escape_string(%s)",
                "mysqli_stmt::bind_param(%s)",
                "db2_escape_string(%s)",
                "pg_escape_string(%s)",
                "pg_escape_bytea(%s)",)





globalxxx =(            "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "", "",
 "", "", "", "", "", "")







class Slice:
    def __init__(self, filePath, vp = None):
        self.vp = vp
        if self.vp == None:
            self.vp = VulnerabilityPattern("sqli",SQLIentrys,MySQLSanitization,XSSsinks+SQLIsinks)

        self.identation = 0
        content_file = open(filePath, 'r')
        content = content_file.read()
        print(" "*61 + "\n" + "-"*23 + " slice content " + "-"*23 + "\n" + " "*61 + "\n" + "\n" + content)
        lines = content.split('\n')
        atributionPatern = re.compile("\$([a-z]\w*)\s*=\s*(.*?)$")
        atribution_completed =[]
        self.slice_order =[]
        imcomplete = False

        print(" " * 60 + "\n" + "-" * 23 + " parsing tree " + "-" * 23 + "\n" + " " * 60 + "\n")
        for line in lines:
            if imcomplete:
                new = atribution_completed[len(atribution_completed) - 1] +" " + line
                atribution_completed.pop()
                atribution_completed.append(new)
                if line.endswith(';'):
                    imcomplete = False
                    self.slice_order.append(PHPatribution(new,self.identation+1, self.vp))

            elif atributionPatern.match(line) != None:
                if line.endswith(';'):
                    atribution_completed.append(line)
                    self.slice_order.append(PHPatribution(line, self.identation+1, self.vp))
                else:
                    imcomplete = True
                    atribution_completed.append(line)
                    #slice_order.append(PHPatribution(line, self.identation+1))

            elif line.startswith('<') & line.endswith('>;'):
                atribution_completed.append(line)
                self.slice_order.append(HTMLline(line, self.identation+1,self.vp))

            elif IsSink(line, self.vp):
                atribution_completed.append(line)
                self.slice_order.append(Sink(line, self.identation+1,self.vp))



        print("\n")
        self.process()
        print("\n")

    def process(self):
        print(" " * 63 + "\n" + "-" * 23 + " tree processing " + "-" * 23 + "\n" + " " * 63 + "\n")
        vars = {}#this is a dictionary
        for e in self.slice_order:
            e.process(vars, self.vp)


def IsSink(line, vpatern):
    for sinkType in vpatern.sensitive_sinks:
        if re.search(sinkType, line) != None:
            return True
    return False


class var:
    def __init__(self, name,integrity):
        self.name = name;
        self.integrity = integrity
        print("var: " + name + "integrity: " + integrity)


class PHPatribution:
    def __init__(self, string,identation, vpatern):
        print(identation*"\t" +"atribution: "+string)
        self.identation = identation
        split = string.split("=",1);
        self.left = PHPvar(split[0],identation+1, vpatern);
        self.right = getRValueType(split[1],identation+1, vpatern);


    def process(self, vars, vpatern):
        integrity = self.right.process(vars, vpatern)
        vars[self.left.name] = integrity
        print(vars)
        return integrity



class HTMLline:
    def __init__(self, string,identation,vpatern):
        self.identation = identation
        print(identation * "\t" + "HTMLline: " + string)
        self.vars = []
        for sink in XSSsinks:
            if re.search("(.*?<?php\s*" + sink + "\s*\$[a-z]\w*\s*.*?)", string) != None:
                groups = re.findall("(.*?<?php\s*" + sink + "\s*\$[a-z]\w*\s*.*?)", string)
                for cut in groups:
                    var = re.search(".*?<?php\s*" + sink + "\s*(\$[a-z]\w*)\s*.*?", cut).groups()
                    self.vars.append(PHPvar(var[0], identation + 1, vpatern))

        self.string = string;

    def process(self, vars,vpatern):
        for var in self.vars:
            if vars.get(var.name) != None:
                if vars.get(var.name) == "low":
                    print("X--> XSS in " + self.string + " because of " + var.name)
                    return "low"
        return "high"

class SQLsink:
    def __init__(self, string,identation,vpatern):
        self.identation = identation
        print(self.identation * "\t" + "SQLsink: " + string)
        self.string = string;
        self.vars = []

        groups = re.findall("\s*(\$[a-z]\w*)\s*", string)
        for cut in groups:
            self.vars.append(PHPvar(cut, identation + 1,vpatern))

    def process(self, vars,vpatern):
        integrity = "high"
        for var in self.vars:
            if vars.get(var.name) != None:
                if vars.get(var.name) == "low":
                    print("X--> SQLI in " + self.string + " because of " + var.name)
                    integrity = "low"
        return integrity

class Sink:
    def __init__(self, string,identation,vpatern):
        self.identation = identation
        print(self.identation * "\t" + "Sink: " + string)
        self.string = string;
        self.vars = []
        self.entries =[]

        groups = re.findall("\s*(\$[a-z]\w*)\s*", string)
        for cut in groups:
            self.vars.append(PHPvar(cut, identation + 1,vpatern))

        #groups = re.findall("\s*(\$_[a-z]\w*)\s*", string)
        for entryType in vpatern.entry_points:
            groups = re.findall("\s*(\\"+ entryType +"\[['a-zA-Z0-9]*\])\s*", string)
            for cut in groups:
                self.entries.append(PHPentry(cut, identation+1, vpatern))


    def process(self, vars,vpatern):
        integrity = "high"
        for var in self.vars:
            if vars.get(var.name) != None:
                if vars.get(var.name) == "low":
                    print("X-->"+vpatern.vulnerabillity_name+" in " + self.string + " because of " + var.name)
                    integrity = "low"
        for entry in self.entries:
            print("X--> "+vpatern.vulnerabillity_name+" in " + self.string + " because of " + entry.string)
            integrity = "low"
        return integrity



class PhpStrings:
    def __init__(self, string,identation, vpatern):
        self.identation = identation
        print(identation * "\t" + "PhpStrings: " + string)
        self.string = string;
        self.vars = []
        groups = re.findall("\s*\'(\$[a-z]\w*)\'\s*", string)
        for cut in groups:
            self.vars.append(PHPvar(cut, identation + 1, vpatern))

    def process(self, vars,vpatern):
        for var in self.vars:
            if vars.get(var.name) != None:
                if vars.get(var.name) == "low":
                    return "low"
        return "high"

class Sanitization:
    def __init__(self, string, identation, vpatern):
        self.identation = identation
        print(identation * "\t" + "Sanitization: " + string)
        self.string = string;
        self.vars = []
        groups = re.findall("\s*(\$[a-z]\w*)\s*", string)
        for cut in groups:
            self.vars.append(PHPvar(cut, identation + 1, vpatern))

    def process(self, vars,vpatern):
        return "high"


class PHPentry:
    def __init__(self, string,identation,vpatern):
        print(identation * "\t" + "PHPentry: " + string)
        self.string = string;

    def process(self, vars, vpatern):
        return "low"


class PHPvar:
    def __init__(self, string, identation,vpatern):
        print(identation * "\t" + "PHPvar: " + string)
        self.name = string;

    def process(self, vars,vpatern):
        if vars.get(self.name) != None:
                    return vars.get(self.name)
        return "low"


class VulnerabilityPattern:
        def __init__(self, vulnerabillity_name, entry_points, sanitization_functions, sensitive_sinks):
            self.vulnerabillity_name = vulnerabillity_name;
            self.entry_points = entry_points;
            self.sanitization_functions = sanitization_functions;
            self.sensitive_sinks = sensitive_sinks;

"a"
def getRValueType(string,identation,vpatern):
    str = string.strip()

    for entryType in vpatern.entry_points:
        if str.startswith(entryType):
            return PHPentry(str,identation,vpatern)
    for sanitize_type in vpatern.sanitization_functions:
        if str.startswith(sanitize_type):
            return Sanitization(str,identation,vpatern)
    if str.startswith('\"') & str.endswith('\";'):
        return PhpStrings(str,identation,vpatern)
    for sinkType in vpatern.sensitive_sinks:
        if re.search(sinkType, str) != None:
            return Sink(str,identation,vpatern)
    if str.startswith("$"):
        return PHPvar(str,identation,vpatern)

def getEntrysInSink(string,identation,vpatern):
    vars = []

    groups = re.findall("\s*(\$[a-z]\w*)\s*", string)
    for entry in groups:
        found = False
        for entryType in vpatern.entry_points:
            if entry.startswith(entryType):
                vars.append(PHPentry(entry, identation, vpatern))
                found = True
        if not found:
            vars.append(PHPvar(cut, identation + 1, vpatern))

"xxx".strip(" ")
