#search non zero xor
# @author: Allsafe
# @category: tools

from ghidra.program.model.listing import CodeUnit

def add_bookmark_comment(addr, text):
	cu = currentProgram.getListing().getCodeUnitAt(addr)
	createBookmark(addr, "non zero xor", text)
	cu.setComment(CodeUnit.EOL_COMMENT, text)

def getFunctionNameAtAddress(address):
    function = getFunctionContaining(address)
    if function is not None:
        return function.getName()
    else:
        return "No function at specified address"

#get all memory ranges
ranges = currentProgram.getMemory().getAddressRanges()
print("--------------------------------")

instructions = currentProgram.getListing().getInstructions(True)

for ins in instructions:
        mnemonic = ins.getMnemonicString()
        if mnemonic == "XOR":
            operand1 = ins.getOpObjects(0)
            operand2 = ins.getOpObjects(1)
            if operand1 != operand2:
                print("{} {} '{}'".format(ins.address,  getFunctionNameAtAddress(ins.address), ins))
                add_bookmark_comment(ins.address, str(ins))
        ins =  getInstructionAfter(ins)
