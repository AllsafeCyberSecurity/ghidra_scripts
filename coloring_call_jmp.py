from ghidra.program.model.listing import CodeUnit
from ghidra.app.plugin.core.colorizer import ColorizingService
from java.awt import Color

#get all memory ranges
ranges = currentProgram.getMemory().getAddressRanges()
print("--------------------------------")

service = state.getTool().getService(ColorizingService)
if service is None:
     print "Can't find ColorizingService service"

for r in ranges:
    begin = r.getMinAddress()
    length = r.getLength()

    ins = getInstructionAt(begin)
    while(ins==None):
        ins =  getInstructionAfter(ins)
    for i in range(length):
        mnemonic = ins.getMnemonicString()
        if mnemonic == "CALL":
            service.setBackgroundColor(ins.address, ins.address, Color(3,169,244))
        elif mnemonic == "JE" or mnemonic == "JZ" or mnemonic == "JNE" or mnemonic == "JNZ" or mnemonic == "JA" or mnemonic == "JAE" or mnemonic == "JBE" or mnemonic == "JB" or mnemonic == "JL" or mnemonic == "JLE" or mnemonic == "JG" or mnemonic == "JGE":
            service.setBackgroundColor(ins.address, ins.address, Color(205,220,57))
        ins =  getInstructionAfter(ins)
        while(ins==None):
            ins =  getInstructionAfter(ins)
