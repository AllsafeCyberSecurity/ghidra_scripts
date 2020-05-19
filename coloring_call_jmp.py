#coloring call and jmp instruction
# @author: Allsafe
# @category: tools

from java.awt import Color

CALL_COLOR = Color(3,169,244)
CONDITIONAL_COLOR = Color(205,220,57)

call_color_count = 0
conditional_color_count = 0

#get all memory ranges
addr_ranges = currentProgram.getMemory().getAddressRanges()

for addr_range in addr_ranges:
    insts = currentProgram.getListing().getInstructions(addr_range.getMinAddress(), True)
    for inst in insts:
        flow_type = inst.getFlowType()
        if flow_type.isCall():
            setBackgroundColor(inst.getAddress(), CALL_COLOR)
            call_color_count += 1
        elif flow_type.isConditional():
            setBackgroundColor(inst.getAddress(), CONDITIONAL_COLOR)
            conditional_color_count += 1
        

print('colored Call: {}'.format(call_color_count))
print('colored Conditional: {}'.format(conditional_color_count))