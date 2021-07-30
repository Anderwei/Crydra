import pefile
import sys

pe = pefile.PE(sys.argv[1])

for section in pe.sections:
    print(str(section.Name)[2:-1].strip("\\x00"),hex(section.VirtualAddress),hex(section.PointerToRawData))
    