from subprocess import check_output,PIPE

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
from ghidra.program.flatapi import FlatProgramAPI

from ghidra.app.plugin.core.instructionsearch import *

from javax.swing import JFrame,JLabel,JButton,BoxLayout,JPanel,SwingConstants
from java.awt import BorderLayout
from java.awt.event import ActionListener


import ast

SCRIPT_PATH = "/home/ander/Crydra/"

CRYFIND_PATH = SCRIPT_PATH + "cryfind/cryfind"
PE_READER_PATH = SCRIPT_PATH + "peReader.py"
PROGRAM_PATH = currentProgram.getExecutablePath()

frame = JFrame("Crydra")

isScriptIsFinish = False

centerPanel = JPanel()
centerPanel.setLayout(BorderLayout())
frame.add(centerPanel)

label1 = JLabel("Click Ok to run script.",SwingConstants.CENTER)
label1.setHorizontalAlignment(JLabel.CENTER)

def runScript(event):

    global isScriptIsFinish

    if isScriptIsFinish:
        frame.dispose()
    

    FPAPI = FlatProgramAPI(currentProgram)
    FPAPI.start()

    result = check_output(["python3",CRYFIND_PATH,"-m","all",PROGRAM_PATH])

    blocks = result.split("\n\n")

    group = []
    for i in blocks[0].split("\n"):
        group.append(ast.literal_eval(i))

    section_table = check_output(["python3",PE_READER_PATH,PROGRAM_PATH])

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
    
    FPAPI.end(True)

    label1.setText("Finished. Click Ok to close window.")
    isScriptIsFinish = True
    


# frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)


confirmButton = JButton("Ok",actionPerformed = runScript)


labelPanel = JPanel()
labelPanel.setLayout(BorderLayout())

centerPanel.add(labelPanel,BorderLayout.CENTER)

labelPanel.add(label1,BorderLayout.CENTER)
labelPanel.add(confirmButton,BorderLayout.SOUTH)


frame.setSize(200,200)
frame.setLocationRelativeTo(None)
frame.setVisible(True)

