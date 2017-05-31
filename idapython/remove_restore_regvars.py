import idc
import idautils
import idaapi


REGISTERS = ["rax", "rdi"]


# Removes the renaming of all registers.
def remove_regvars(func_addr):
    func = idaapi.get_func(func_addr)

    # Store register renaming.
    addr = func.startEA
    regvars = set()
    while addr <= func.endEA:
        for reg_str in REGISTERS:
            regvar = idaapi.find_regvar(func, addr, reg_str)
            if regvar is not None:

                regvars.add((reg_str,
                             regvar.user,
                             regvar.cmt,
                             regvar.startEA,
                             regvar.endEA))
        addr += 1

    # Remove register renaming.
    for regvar in regvars:
        idaapi.del_regvar(func,
                          regvar[3], # startEA
                          regvar[4], # endEA
                          regvar[0]) # register string

    return regvars


# Restores all removed register renamings.
def restore_regvars(func_addr, regvars):
    func = idaapi.get_func(func_addr)
    for regvar in regvars:
        idaapi.add_regvar(func,
                          regvar[3], # startEA
                          regvar[4], # endEA
                          regvar[0], # register string
                          regvar[1], # user register string
                          regvar[2]) # comment


segments = list(idautils.Segments())
for segment in segments:
    if idc.SegName(segment) == ".plt":
        plt_seg = segment
        plt_start = idc.SegStart(plt_seg)
        plt_end = idc.SegEnd(plt_seg)

for segment in segments:
    permissions = idaapi.getseg(segment).perm
    if not permissions & idaapi.SEGPERM_EXEC:
        continue

    if idc.SegStart(segment) == plt_start:
        continue

    print('\nProcessing segment %s.' % idc.SegName(segment))
    for i, func_addr in enumerate(idautils.Functions(idc.SegStart(segment),
        idc.SegEnd(segment))):

        print("Removing regvars for 0x%x" % func_addr)
        regvars = remove_regvars(func_addr)

        # DO STUFF THAT DEPENDS ON NORMAL REGISTER NAMES

        print("Restoring regvars for 0x%x" % func_addr)
        restore_regvars(func_addr, regvars)