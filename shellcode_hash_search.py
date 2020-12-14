#search shellcode hashes
# @author: Allsafe
# @category: tools

import json
from ghidra.program.model.listing import CodeUnit
from ghidra.util.exception import CancelledException
from ghidra.program.model.scalar import Scalar

def add_bookmark_comment(addr, text):
	cu = currentProgram.getListing().getCodeUnitAt(addr)
	createBookmark(addr, "shellcode_hash", text)
	cu.setComment(CodeUnit.EOL_COMMENT, text)

try:
    sc_hashes_file = askFile("sc_hashes.json", "sc_hashes.json").getPath()
except CancelledException as e:
    print str(e)
    exit()

with open(sc_hashes_file, 'r') as f:
     sc_hashes = json.load(f)

def  db_search(data):
    if isinstance(data[0], Scalar):
        decimal_data= int(str(data[0]), 16)
        try:
            return sc_hashes['symbol_hashes'][str(decimal_data)]
    	except:
            return -1

#get all instructions
instructions = currentProgram.getListing().getInstructions(True)

print("--------------------------------")

for ins in instructions:
    mnemonic = ins.getMnemonicString()
    if mnemonic == "MOV":
        operand2 = ins.getOpObjects(1)
        symbol_info = db_search(operand2)
        if symbol_info != -1 and symbol_info != None:
            text = "{} {} [{}]{}".format(ins.address, sc_hashes['hash_types'][str(symbol_info['hash_type'])], sc_hashes['source_libs'][str(symbol_info['lib_key'])], symbol_info['symbol_name'])
            print(text)
            add_bookmark_comment(ins.address, text)
    elif mnemonic == "PUSH":
        operand1 = ins.getOpObjects(0)
        symbol_info = db_search(operand1)
        if symbol_info != -1 and symbol_info != None:
            text = "{} {} [{}]{}".format(ins.address, sc_hashes['hash_types'][str(symbol_info['hash_type'])], sc_hashes['source_libs'][str(symbol_info['lib_key'])], symbol_info['symbol_name'])
            print(text)
            add_bookmark_comment(ins.address, text)
