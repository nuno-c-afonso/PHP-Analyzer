from PHPparser import *
from VulnerabilityPattern import *

path = os.environ['HOME'] +  "/projSS/proj-slicesX/"
#path = "/home/diogo/Desktop/projSS/proj-slicesX/"
print path

files = ["sqli_01.txt","sqli_02.txt","sqli_03.txt","sqli_04.txt","sqli_05.txt","xss_01.txt","xss_02.txt","xss_03.txt"]#,
        #"teste.txt" ]
#files = ["sqli_04.txt"]
#files = ["teste.txt"]
slices = []
for file in files:
    print("\n" + "\n" + "#" * 63 + "\n" + "#" * 23 + file + "#" * 23 + "\n" + "#" * 63 + "\n")
    slices.append(Slice(path + file))

#for slice in slices:
#    slice.process()



# string = re.