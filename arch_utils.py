# settings set target.x86-disassembly-flavor intel / default / att
# command script import "C:\\Program Files (x86)\\Embarcadero\\Studio\\37.0\\bin\\windows\\lldb\\arch_utils.py"
# command script add -f arch_utils.cmd_is_branch_or_call is_branch_or_call
# command script add -f arch_utils.cmd_get_operands get_operands
# command script add -f arch_utils.cmd_get_arch_name get_arch_name
# process launch

# Read 4 bytes (--size), format (--format) x (hex), at address 0xaa214 count (-c) of 1
# memory read --size 4 --format x 0xaa214 -c 1

import lldb

debug_mode = False

# Constants for architecture grouping
ARCH_X86 = ("i386", "x86", "x86_64", "amd64")
ARCH_ARM = ("arm", "thumb", "armv7")
ARCH_ARM64 = ("aarch64", "arm64")
ARCH_ALL_ARM = ARCH_ARM + ARCH_ARM64

def get_x86_flavor(debugger):
    # This returns an SBStructuredData containing the setting info
    # But usually, it's easier to just run the command and parse output
    # or look it up via the command interpreter's "GetSetting" mechanism.

    # Method A: Using HandleCommand (simplest for text output)
    res = lldb.SBCommandReturnObject()
    debugger.GetCommandInterpreter().HandleCommand("settings show target.x86-disassembly-flavor", res)
    if res.Succeeded():
        # Output looks like: "target.x86-disassembly-flavor (enum) = intel"
        output = res.GetOutput().strip()
        # Parse the value after " = "
        if " = " in output:
            return output.split(" = ")[-1]
    return "default"  # Fallback

def _get_arch_name(target):
    triple = target.GetTriple()
    return triple.split("-")[0].lower() if triple else ""

def is_int_literal(s: str) -> bool:
    try:
        int(s.strip(), 0)  # base=0 accepts 0x.., 0b.., 0o.., or decimal
        return True
    except ValueError:
        return False

def cmd_get_arch_name(debugger, command, exe_ctx, result, internal_dict):
    target = exe_ctx.target
    arch = _get_arch_name(target)
    result.PutCString("Architecture: %s" % arch)

def _resolve_register_value(frame, reg_name, result_out=None):
    """
    Return integer value of register reg_name in this frame, or None.
    Handles common register name variations (edx/EDX/%edx, rax/RAX/%rax, etc.).
    """
    if not frame or not frame.IsValid():
        return None

    # Normalize register name: strip % prefix, try original/capitalized/lowercase
    reg_name_norm = reg_name.lstrip('%').strip()
    if result_out:
        result_out.PutCString("reg_name_norm: %s" % reg_name_norm)
    reg_variants = [reg_name_norm, reg_name_norm.upper(), reg_name_norm.lower()]
    if result_out:
        result_out.PutCString("reg_variants: %s" % reg_variants)

    for reg_candidate in reg_variants:
        reg = frame.FindRegister(reg_candidate)
        if result_out:
            result_out.PutCString("_resolve_register_value reg: %s" % reg)
        if reg and reg.IsValid():
            if result_out:
                result_out.PutCString("Inside reg and reg.IsValid()")
            val = reg.GetValue()
            if result_out:
                result_out.PutCString("_resolve_register_value val: %s" % val)
            if val is not None:
                try:
                    if result_out:
                        result_out.PutCString("_resolve_register_value return: %s" % int(val, 0))
                    return int(val, 0)  # auto-detects hex/decimal
                except (ValueError, TypeError):
                    continue

    return None

def _is_branch_or_call_kind(controlFlowKind):
    kind = controlFlowKind in (
        lldb.eInstructionControlFlowKindCall,
        lldb.eInstructionControlFlowKindJump,
        lldb.eInstructionControlFlowKindCondJump,
        lldb.eInstructionControlFlowKindFarJump,
    )
    return kind

def is_branch_or_call_at_addr(target, addr_load, flavor, frame=None, result_out=None):
    """
    Given an lldb.SBTarget and a load address (integer),
    return (is_branch_or_call, target_addr_or_None).

    If 'frame' is provided (SBFrame), it will be used to resolve
    register-indirect targets like:
      - x86/x64: call dword ptr [edx], jmp dword ptr [edx], jmp [rax], jmp edx
      - ARM:     blx r3, bx r4
      - ARM64:   bl x3, br x4  (when LLDB prints reg as operand)
    """
    if debug_mode and result_out:
        result_out.PutCString("DEBUG: is_branch_or_call_at_addr checking 0x%x" % addr_load)
        result_out.PutCString("Disassembly flavor: %s" % flavor)

    if not target or not target.IsValid():
        return (False, None)

    arch = _get_arch_name(target)
    if debug_mode and result_out:
        result_out.PutCString("DEBUG: is_branch_or_call_at_addr arch: %s" % arch)

    # sb_addr = target.ResolveLoadAddress(addr_load)
    sb_addr = target.ResolveFileAddress(addr_load)
    if debug_mode and result_out:
        result_out.PutCString("DEBUG: is_branch_or_call_at_addr sb_addr %s" % str(sb_addr))
    if not sb_addr or not sb_addr.IsValid():
        return (False, None)

    # Read raw bytes from memory; this returns a Python bytes object on your build
    err = lldb.SBError()
    buf = target.ReadMemory(sb_addr, 32, err)  # 32 bytes is enough for one instruction
    if not err.Success() or not buf:
        return (False, None)

    inst_list = target.GetInstructions(sb_addr, buf)
    if inst_list.GetSize() == 0:
        return (False, None)

    inst = inst_list.GetInstructionAtIndex(0)
    if debug_mode and result_out:
        result_out.PutCString("DEBUG: is_branch_or_call_at_addr inst: %s" % inst)
    if not inst or not inst.IsValid():
        return (False, None)

    controlFlowKind = inst.GetControlFlowKind(target);
    if debug_mode and result_out:
        kind_name_map = {
            lldb.eInstructionControlFlowKindUnknown: "Unknown",
            lldb.eInstructionControlFlowKindCall: "Call",
            lldb.eInstructionControlFlowKindReturn: "Return",
            lldb.eInstructionControlFlowKindJump: "Jump",
            lldb.eInstructionControlFlowKindCondJump: "CondJump",
            lldb.eInstructionControlFlowKindFarCall: "FarCall",
            lldb.eInstructionControlFlowKindFarReturn: "FarReturn",
            lldb.eInstructionControlFlowKindFarJump: "FarJump",
        }
        result_out.PutCString("ControlFlowKind: %s" % kind_name_map.get(controlFlowKind, str(controlFlowKind)))
        mnemonic = inst.GetMnemonic(target)
        result_out.PutCString("mnemonic: %s" % mnemonic)
    # if not _is_branch_or_call_mnemonic(mnemonic, arch):
    #     return (False, None)
    if not _is_branch_or_call_kind(controlFlowKind):
        return (False, None)

    operands_str = inst.GetOperands(target)
    if debug_mode and result_out:
        result_out.PutCString("Operands: %s" % operands_str)
    tokens = operands_str.replace(",", " ").split()
    if not tokens:
        # Branch/call with no parsable operands
        return (True, None)
		
    # Full operand string (for x86 "[edx]" or "dword ptr [edx]",
    # ARM/ARM64 "r3", "x4", etc.)
    op_full = operands_str
    cand = tokens[0].split(";")[0].strip()
    if debug_mode and result_out:
        result_out.PutCString("op_full: %s" % op_full)
        result_out.PutCString("cand: %s" % cand)

    target_addr = None

    if debug_mode and result_out:
        result_out.PutCString("DEBUG: op_full: %s" % op_full)

    # --- 1) Register-indirect forms ---
    # x86/x64 example: "dword ptr [edx]" or "[edx]" or "qword ptr [rax]"
    if arch in ARCH_X86:
        if debug_mode and result_out:
            result_out.PutCString("arch in ARCH_X86")

        ptr_addr = None
        indirect = False
        target_addr = None

        # Intel syntax: "dword ptr [edx]" or "[edx]", which appears not to be used, even
        # though disassembly flavor is set to Intel
        if "[" in op_full and "]" in op_full:
            if debug_mode and result_out:
                result_out.PutCString("Intel disassembly mode")
            indirect = True
            inside = op_full[op_full.find("[") + 1: op_full.find("]")]
            inside = inside.strip()

            # Case A: Absolute address "[0x5c15a0]"
            try:
                ptr_addr = int(inside, 0)
                if debug_mode and result_out:
                    result_out.PutCString("DEBUG: Intel syntax, absolute addr: 0x%x" % ptr_addr)
            except ValueError:
                # Case B: Register + Offset "[ebp - 0x8]" or "[ebp + 0x10]" or Just Register "[ebp]"
                # Simple parser: look for '+' or '-'
                import re
                # Split by + or - but keep the delimiter
                parts = re.split(r'(\+|\-)', inside)

                base_val = 0

                # 1. Resolve Base (first part)
                base_str = parts[0].strip()
                reg_val = _resolve_register_value(frame, base_str)

                if reg_val is not None:
                    base_val = reg_val
                else:
                    # Maybe the base is a number? (unlikely for Intel syntax usually [reg+off])
                    try:
                        base_val = int(base_str, 0)
                    except ValueError:
                        base_val = None

                if base_val is not None:
                    ptr_addr = base_val
                    # 2. Process Offset if exists
                    if len(parts) >= 3:
                        operator = parts[1].strip()
                        offset_str = parts[2].strip()
                        try:
                            offset_val = int(offset_str, 0)
                            if operator == '+':
                                ptr_addr += offset_val
                            elif operator == '-':
                                ptr_addr -= offset_val
                        except ValueError:
                            # Failed to parse offset, abort
                            ptr_addr = None

                if debug_mode and result_out:
                    result_out.PutCString(
                        "DEBUG: Intel syntax, resolved ptr_addr: %s" % (hex(ptr_addr) if ptr_addr is not None else "None"))

        # New updated AT&T syntax: "*(%edx)" or "*-0x8(%ebp)" or "*0xb15a0" or "*%rax"
        elif op_full.startswith("*"):
            if debug_mode and result_out:
                result_out.PutCString("AT&T disassembly mode")
            expr = op_full[1:].strip()  # Strip '*'
            if debug_mode and result_out:
                result_out.PutCString("expr: %s" % expr)

            # Case 1: Register-indirect with optional displacement "*(%edx)", "*-0x8(%ebp)"
            # equivalent to [EDX], [EBP-8]
            if "(%" in expr and expr.endswith(")"):
                if debug_mode and result_out:
                    result_out.PutCString("Handling case 1)")
                indirect = True
                idx_open = expr.rfind("(")
                # part before '(' is displacement
                offset_str = expr[:idx_open].strip()
                if len(offset_str) == 0:
                    offset_str = '0'
                # part inside '(%...)' is register
                inside = expr[idx_open + 1:-1].strip()
                reg_name = inside.lstrip("%")

                if debug_mode and result_out:
                    result_out.PutCString("DEBUG: AT&T syntax, reg_name: %s, offset: %s" % (reg_name, offset_str))

                base_val = _resolve_register_value(frame, reg_name)
                if base_val is not None:
                    ptr_addr = base_val
                    if debug_mode and result_out:
                        result_out.PutCString("DEBUG: AT&T syntax, reg_name: %s, value: %s" % (reg_name, hex(ptr_addr)))
                    if offset_str:
                        try:
                            offset_val = int(offset_str, 0)
                            ptr_addr += offset_val
                        except ValueError:
                            ptr_addr = None

            # Case 2: Absolute indirect "*0xb15a0" -> read memory at 0xb15a0
            elif expr.startswith("0x") or (len(expr) > 0 and expr[0].isdigit()) or expr.startswith("-"):
                if debug_mode and result_out:
                    result_out.PutCString("DEBUG: AT&T syntax, absolute indirect: %s" % expr)
                indirect = True
                try:
                    ptr_addr = int(expr, 0)
                    if debug_mode and result_out:
                        result_out.PutCString("DEBUG: AT&T syntax, absolute addr: 0x%x" % ptr_addr)
                except ValueError:
                    ptr_addr = None

            # Case 3: Direct register "*%eax" -> equivalent to Intel "call eax" (not [eax])
            elif expr.startswith("%"):
                if debug_mode and result_out:
                    result_out.PutCString("DEBUG: AT&T syntax, direct register: %s" % expr)
                indirect = False
                reg_name = expr.lstrip("%")
                if debug_mode and result_out:
                    result_out.PutCString("DEBUG: AT&T syntax, direct register: %s" % reg_name)
                val = _resolve_register_value(frame, reg_name)
                if val is not None:
                    target_addr = val

        else:
            # jmp edx, call edx, je 0x123456
            if debug_mode and result_out:
                result_out.PutCString("Direct register / direct address / relative address")
            indirect = False
            inside = op_full
            if debug_mode and result_out:
                result_out.PutCString("Direct register / direct address, inside: %s" % inside)
            reg_token = inside.strip().split()[0]
            if not is_int_literal(reg_token):
                if debug_mode and result_out:
                    result_out.PutCString("DEBUG: Direct register / indirect address, reg_token: %s" % reg_token)
                reg_name = reg_token.lstrip('*').strip()
                if debug_mode and result_out:
                    result_out.PutCString("DEBUG: Direct register, reg_name: %s" % reg_name)
                ptr_addr = _resolve_register_value(frame, reg_name)
                target_addr = ptr_addr
                if debug_mode and result_out:
                    result_out.PutCString("target_addr = %s" % target_addr)

        if ptr_addr is not None and indirect:
            if debug_mode and result_out:
                result_out.PutCString("ptr_addr is not None and indirect")
            err = lldb.SBError()
            target_addr_size = target.GetAddressByteSize() # 32-bit vs 64-bit
            sb_mem_addr = target.ResolveLoadAddress(ptr_addr)
            if debug_mode and result_out:
                result_out.PutCString("DEBUG: Indirect, sb_mem_addr: 0x%x" % sb_mem_addr.GetLoadAddress(target))
            # target_bytes = target.ReadMemory(target.ResolveLoadAddress(ptr_addr), target_addr_size, err)
            target_bytes = target.ReadMemory(sb_mem_addr, target_addr_size, err)
            if debug_mode and result_out:
                result_out.PutCString("DEBUG: Indirect, target_bytes: %s" % target_bytes)
            if err.Success() and target_bytes and len(target_bytes) == target_addr_size:
                is_little = target.GetByteOrder() == lldb.eByteOrderLittle
                target_addr = int.from_bytes(target_bytes, byteorder='little' if is_little else 'big')
                if debug_mode and result_out:
                    result_out.PutCString("DEBUG: target_addr: %s" % hex(target_addr))

    # ARM / ARM64 example: "blx r3", "bx r4", "br x5", "bl x6"
    if target_addr is None and arch in ARCH_ALL_ARM and frame is not None:
        # LLDB usually prints just the register as operand, e.g. "r3" or "x5"
        reg_name = cand  # first token (e.g. "r3", "x5")
        # Strip possible condition codes or punctuation (unlikely here)
        reg_name = reg_name.strip()
        # Try direct register resolution
        ptr_val = _resolve_register_value(frame, reg_name)
        if ptr_val is not None:
            target_addr = ptr_val

    # --- 2) Direct hex address (all archs) ---
    if target_addr is None and cand.startswith("0x"):
        if debug_mode and result_out:
            result_out.PutCString("Handling case 2)")
        try:
            target_addr = int(cand, 16)
        except ValueError:
            target_addr = None
			
    # --- 3) Symbol name (all archs) ---
    if target_addr is None and not cand.startswith("0x"):
        # Untested branch
        if debug_mode and result_out:
            result_out.PutCString("Handling case 3)")
        syms = target.FindSymbols(cand)
        if syms.GetSize() > 0:
            sym = syms.GetContextAtIndex(0).GetSymbol()
            if sym and sym.IsValid():
                sa = sym.GetStartAddress()
                if sa and sa.IsValid():
                    target_addr = sa.GetLoadAddress(target)

    # --- 4) Simple PC-relative handling ---
    # This appears to be handled under Case 2) already...
    if target_addr is None:
        if debug_mode and result_out:
            result_out.PutCString("Handling case 4)")
        inst_addr = inst.GetAddress()
        if inst_addr and inst_addr.IsValid():
            pc = inst_addr.GetLoadAddress(target)
            if arch in ARCH_X86:
                try:
                    # target_addr = x86_cond_jump_target_from_inst(target, inst)
                    target_addr = op_full
                    if debug_mode and result_out:
                        result_out.PutCString("target_addr: %s" % hex(target_addr))
                except ValueError:
                    pass
            else:
                # Untested branch for non-x86/x64 targets
                target_addr = pc

    # --- 5) Register-direct handling for x86/x64 (e.g. "jmp rax") ---
    if target_addr is None and arch in ARCH_X86 and frame is not None:
        # Try resolving 'cand' as a register name directly
        if debug_mode and result_out:
            result_out.PutCString("Handling case 5)")
        val = _resolve_register_value(frame, cand)
        if val is not None:
            target_addr = val

    return (True, target_addr)

def cmd_is_branch_or_call(debugger, command, exe_ctx, result, internal_dict):
    """
    Usage:
      is_branch_or_call <address>
    """
    global debug_mode
    target = exe_ctx.target
    frame = exe_ctx.frame
    if not target or not target.IsValid():
        result.PutCString("No valid target.")
        return

    cmd = command.strip()
    if not cmd:
        result.PutCString("Usage: is_branch_or_call <address>")
        return

    cmd_args = command.strip().split()
    if len(cmd_args) < 1:
        result.PutCString("Usage: is_branch_or_call <address> [debug]")
        return

    try:
        addr = int(cmd_args[0], 0)
    except ValueError:
        result.PutCString("Invalid address: %s" % cmd_args[0])
        return

    debug_mode = len(cmd_args) > 1 and cmd_args[1] == "debug"
    current_flavor = get_x86_flavor(debugger)
    if debug_mode:
        result.PutCString("=== DEBUG: Analyzing 0x%x ===" % addr)
        result.PutCString("Disassembly flavor = %s" % current_flavor)
        result.PutCString("Arch: %s" % _get_arch_name(target))
        result.PutCString("Frame valid: %s" % frame.IsValid())
        result.PutCString("Target: %s" % str(target))

    is_br, tgt = is_branch_or_call_at_addr(target, addr, current_flavor, frame, result)

    if debug_mode:
        result.PutCString("Raw result: is_branch=%s, target=%s" % (is_br, hex(tgt) if tgt else "None"))

    if not is_br:
        result.PutCString("Instruction at 0x%x is NOT a branch/call." % addr)
    elif tgt is None:
        result.PutCString(
            "Instruction at 0x%x IS a branch/call, but target could not be resolved."
            % addr
        )
    else:
        result.PutCString(
            "Instruction at 0x%x IS a branch/call; target = 0x%x." % (addr, tgt)
        )
