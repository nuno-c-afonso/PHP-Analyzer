class colors:
    BLACK   =   '\033[30m'
    RED     =   '\033[31m'
    BRED    = '\x1b[31;4m'
    BREDRESET = '\x1b[5;39;49m'

    GREEN   =   '\033[32m'
    BGREEN  = '\x1b[1;30;42m'

    YELLOW  =   '\033[33m'
    BYELLOW =   '\033[43m'

    BLUE    =   '\033[34m'
    BYELLOWRED = '\x1b[1;31;43m'

    BLUE2   =   '\033[36m'

    RESET   =   '\033[39m'
    BRESET = '\x1b[5;39;49m'

    BLINK = '\033[4m'

columnSize = 30


testInput = {'$_varHigh': "high", '$_varLow': "low"}
orders =['$_varHigh', '$_varLow']


def getGraphCaption():
    line="Caption: "
    line+= colors.GREEN+"high integrity "+colors.RESET
    line += colors.RED + "low integrity " + colors.BRESET
    line += colors.BLUE2 + "Safe Sink " + colors.RESET
    line += colors.RED+"Sink with vulnerability "+colors.BREDRESET
    return line

def getVarsIntegrityLine(vars, order):
    prevLine = ""
    line = ""
    nextLine = ""

    if len(order) == 0:
        return line

    for var in order:
        if vars.get(var) == "high":
            prevLine += colors.GREEN + ("|").center(columnSize, ' ') + colors.RESET
            line += colors.GREEN + (var + ":high").center(columnSize, ' ') + colors.RESET
            nextLine += colors.GREEN + ("|").center(columnSize, ' ') + colors.RESET
        else:
            prevLine += colors.RED + ("|").center(columnSize, ' ') + colors.RESET
            line += colors.RED + (var + ":low").center(columnSize, ' ') +colors.RESET
            nextLine += colors.RED + ("|").center(columnSize, ' ') + colors.RESET

    return prevLine +"\n" +line +"\n" +nextLine

def getTransformationLine(change, order, changedVar, vars):
    #print(change.string)
    string = change.string[:columnSize].center(columnSize, ' ')
    for var in vars:
        if vars.get(var) == "high":
            string = string.replace(var, colors.GREEN+var+colors.RESET)
        else:
            string = string.replace(var, colors.RED + var + colors.RESET)

    line = ""
    for var in order:
        if var == changedVar:
            line+= string+colors.RESET
        else:
            if vars.get(var) == "high":
                line += colors.GREEN + ("|").center(columnSize, ' ') + colors.RESET
            else:
                line += colors.RED + ("|").center(columnSize, ' ') + colors.RESET

    return line


def getSinkPrintVuln(vulnerabilityName, instructionLine, string, vars, order):
    line = ""
    for var in order:
        if vars.get(var) == "high":
            line += colors.GREEN + ("|").center(columnSize, ' ') + colors.RESET
        else:
            line += colors.RED + ("|").center(columnSize, ' ') + colors.RESET

    old = "\nX-->"+ colors.RED + vulnerabilityName + " in: "+ colors.RESET + instructionLine + " \n" + colors.RED+"    because of: " + string + colors.RESET
    for var in vars:
        if vars.get(var) == "high":
            old= old.replace(var, colors.GREEN+var+colors.RESET)
        else:
            old = old.replace(var, colors.RED + var + colors.RESET)

    line += old

    return line

def getSinkPrintClean(vulnerabilityName,string, vars, order):
    line = ""
    for var in order:
        if vars.get(var) == "high":
            line += colors.GREEN + ("|").center(columnSize, ' ') + colors.RESET
        else:
            line += colors.RED + ("|").center(columnSize, ' ') + colors.RESET

    old ="\nX-->"+ colors.BLUE2 + "No "+ vulnerabilityName +" in: "+ colors.RESET + string+" \n"+ colors.BLUE2 + "    because all args have high Integrity"+ colors.RESET
    for var in vars:
        if vars.get(var) == "high":
            old= old.replace(var, colors.GREEN+var+colors.RESET)
        else:
            old = old.replace(var, colors.RED + var + colors.RESET)


    line += old

    return line

