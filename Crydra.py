from subprocess import check_output,PIPE

from javax.swing import JScrollPane
from javax.swing import JTextArea
from javax.swing import JPanel
from javax.swing import JSplitPane

from java.awt import BorderLayout

import ghidra.app.script.GhidraScript
from  ghidra.program.model.mem import *
from  ghidra.program.model.lang import *
from  ghidra.program.model.pcode import *
from  ghidra.program.model.util import *
from  ghidra.program.model.reloc import *
from  ghidra.program.model.data import *
from  ghidra.program.model.block import *
from  ghidra.program.model.symbol import *
from  ghidra.program.model.scalar import *
from  ghidra.program.model.listing import *
from  ghidra.program.model.address import *

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.model.listing import FunctionManager

from ghidra.app.plugin.core.instructionsearch import *

import ast

SCRIPT_PATH = "/home/your_home_directory/ghidra_scripts/"

CRYFIND_PATH = SCRIPT_PATH + "cryfind/cryfind"
PE_READER_PATH = SCRIPT_PATH + "peReader.py"
PROGRAM_PATH = currentProgram.getExecutablePath()

plugin = util.InstructionSearchUtils.getInstructionSearchPlugin(state.getTool())

class TestDialog(ui.InstructionSearchDialog):

    def __init__(self):
        super(TestDialog,self).__init__(plugin,"Test Pane2",None)

dialog = TestDialog()

dialog.removeWorkPanel()

textArea = JTextArea(0,0)
textAreaScrollPanel = JScrollPane(textArea)
textArea.setWrapStyleWord(True)
textArea.setLineWrap(True)

mainPanel = JPanel()
mainPanel.setLayout(BorderLayout())

mainPanel.add(textAreaScrollPanel)

dialog.addWorkPanel(mainPanel)  

dialog.setPreferredSize(500,400)

state.getTool().showDialog(dialog)

result = check_output(["python3",CRYFIND_PATH,"-m","all",PROGRAM_PATH])

# textArea.setText(result)

blocks = result.split("\n\n")

group = []
for i in blocks[0].split("\n"):
    group.append(ast.literal_eval(i))
# print(group)
'''
{'AES [td3]':
[
    {'fullword': [(0, 4258815405114008044879095782865203932458957003094248837144746484503916178477203374401096202500586882061160878856353236580258228933404919076282731944977250L, 'big', 264452)]},
    {'dword': [(0, 1364240372, 'big', 268876), (1, 2119394625, 'big', 268584), (2, 449029143, 'big', 268972), (3, 982933031, 'big', 269400), (4, 1003187115, 'big', 268740), (5, 535905693, 'big', 268764), (6, 2896910586L, 'big', 269208), (7, 1267925987, 'big', 268772), (8, 542505520, 'big', 269312), (9, 2918608246L, 'big', 268804), (10, 2291234508L, 'big', 269200), (11, 4112862210L, 'big', 269180), (12, 1341970405, 'big', 269064), (13, 3319253802L, 'big', 269520), (14, 645940277, 'big', 269408), (15, 3046089570L, 'big', 269552)]}]}, {'ZLIB [lengthCodes]': [{'dword': [(0, 16842752, 'big', 32092), (1, 33619968, 'big', 32100), (2, 50397184, 'big', 32108), (3, 67174400, 'big', 32116), (4, 83951616, 'big', 32124), (5, 100728832, 'big', 32131), (6, 117506048, 'big', 32139), (7, 134283264, 'big', 32147), (8, 151060480, 'big', 32155), (9, 151060480, 'big', 32155), (10, 167837696, 'big', 32162), (11, 167837696, 'big', 32162), (12, 184614912, 'big', 32170), (13, 184614912, 'big', 32170), (14, 201392128, 'big', 32178), (15, 201392128, 'big', 32178)]}]}, {'ZLIB [lengthCodes]': [{'dword': [(0, 16842752, 'big', 32092), (1, 33619968, 'big', 32100), (2, 50397184, 'big', 32108), (3, 67174400, 'big', 32116), (4, 83951616, 'big', 32124), (5, 100728832, 'big', 32131), (6, 117506048, 'big', 32139), (7, 134283264, 'big', 32147), (8, 151060480, 'big', 32155), (9, 151060480, 'big', 32155), (10, 167837696, 'big', 32162), (11, 167837696, 'big', 32162), (12, 184614912, 'big', 32170), (13, 184614912, 'big', 32170), (14, 201392128, 'big', 32178), (15, 201392128, 'big', 32178)]}]}]
'''

# print(blocks[1])

section_table = check_output(["python3",PE_READER_PATH,PROGRAM_PATH])

textArea.setText(section_table)
VPK = int([ i.split(" ") for i in section_table.split("\n")[:-1]][0][1],16) - int([ i.split(" ") for i in section_table.split("\n")[:-1]][0][2],16)

FA_To_VA_offset = int(str(currentProgram.getImageBase()),16)  + VPK

output = ""

for cryptType in group:
    for cryptName,cryptGroup in cryptType.iteritems():
        output += cryptName + "\n"
        for consts in cryptGroup:
            for const_data_type,consts_info in consts.iteritems():
                output += const_data_type + "\n"
                for info in consts_info:
                    output += "   " + hex(int(info[1])) + " " + info[2] + " " + hex(int(info[3]) + FA_To_VA_offset) + "\n"
                    target_addr_offset = int(info[3]) + FA_To_VA_offset - int(str(currentProgram.getImageBase()),16)
                    createBookmark(currentProgram.getMinAddress().add(target_addr_offset),cryptName, const_data_type + " - " +info[2])
    