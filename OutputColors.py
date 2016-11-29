class colors:
    BLACK   =   '\033[30m'
    RED     =   '\033[31m'
    GREEN   =   '\033[32m'
    YELLOW  =   '\033[33m'
    BLUE    =   '\033[34m'
    RESET   =   '\033[39m'



testInput = {'$_varHigh': "high", '$_varLow': "low"}

def getVarsIntegrityLine(vars):
    line = "|"
    nextLine = "|"
    for var in vars:
        if vars.get(var) == "high":
            line += colors.GREEN + (var + ":high").center(20, ' ') + colors.RESET
            nextLine += colors.GREEN + ("|").center(20, ' ') + colors.RESET
        else:
            line += colors.RED + (var + ":low").center(20, ' ') +colors.RESET
            nextLine += colors.RED + ("|").center(20, ' ') + colors.RESET
        line += "|"
        nextLine += "|"
    return line +"\n" +nextLine



print(getVarsIntegrityLine(testInput))