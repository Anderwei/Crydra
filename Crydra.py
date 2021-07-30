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
    