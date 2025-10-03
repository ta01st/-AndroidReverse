


import angr
import claripy
import pyvex
from typing import List, Dict, Union, Optional
import os

from typing import List, Dict, Union, Optional
import os
import lief
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, KS_MODE_BIG_ENDIAN
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN

my_patches =[]

AARCH64_NOP_LE = b"\x1f\x20\x03\xd5"   # 0xd503201f (LE)
PT_LOAD = 1

def _norm_addr(a: Union[int, str]) -> int:
    if isinstance(a, int): return a
    s = str(a).strip().lower()
    return int(s, 16) if s.startswith("0x") else int(s)

def _file_is_little_endian(elf_path: str) -> bool:
    with open(elf_path, "rb") as f:
        ident = f.read(6)  # EI_MAG/EI_CLASS/EI_DATA
    if len(ident) < 6: raise ValueError("ELF 文件过短，无法读取 EI_DATA")
    if ident[5] == 1: return True   # LSB
    if ident[5] == 2: return False  # MSB
    raise ValueError(f"未知 EI_DATA 值: {ident[5]}")

def _assemble_arm64_at(asm: str, pc: int, little_endian: bool) -> bytes:
    """按给定 PC 汇编（关键：让 ‘b 绝对地址’ 变成正确的 PC 相对编码）"""
    mode = KS_MODE_LITTLE_ENDIAN if little_endian else KS_MODE_BIG_ENDIAN
    ks = Ks(KS_ARCH_ARM64, mode)
    enc = ks.asm(asm, addr=pc, as_bytes=True)  # ★ 传入 pc
    code = bytes(enc[0] if isinstance(enc, tuple) else enc)
    if len(code) % 4 != 0:
        raise ValueError(f"汇编长度 {len(code)} 不是 4 的倍数；ARM64 指令需 4B 对齐。\nASM:\n{asm}")
    return code

def _pad_or_check(code: bytes, max_len: Optional[int], little_endian: bool) -> bytes:
    if max_len is None: return code
    if max_len % 4 != 0:
        raise ValueError(f"max_len={max_len} 不是 4 的倍数，不适合 ARM64 对齐。")
    if len(code) > max_len:
        raise ValueError(f"编码长度 {len(code)}B > 允许写入 {max_len}B；请缩短汇编或增大 max_len。")
    if len(code) < max_len:
        nop = AARCH64_NOP_LE if little_endian else AARCH64_NOP_LE[::-1]
        code += nop * ((max_len - len(code)) // 4)
    return code

def _seg_filesz(seg) -> int:
    return int(getattr(seg, "file_size", 0) or getattr(seg, "physical_size", 0))

def _seg_memsz(seg) -> int:
    return int(getattr(seg, "virtual_size", 0))

def _seg_vaddr(seg) -> int:
    return int(getattr(seg, "virtual_address", 0))

def _seg_fileoff(seg) -> int:
    return int(getattr(seg, "file_offset", 0))

def _va_to_file_off_via_lief(binary: lief.ELF.Binary, va: int) -> tuple[int, object]:
    for seg in binary.segments:
        p_type = int(getattr(seg, "type", 0))
        if p_type != PT_LOAD: continue
        start = _seg_vaddr(seg); end = start + _seg_memsz(seg)
        if start <= va < end:
            off = _seg_fileoff(seg) + (va - start)
            return off, seg
    raise ValueError(f"VA {hex(va)} 不落在任何 PT_LOAD 段内，无法定位文件偏移。")

def _disasm_for_sanity(code: bytes, va: int, little: bool) -> list[str]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN if little else CS_MODE_BIG_ENDIAN)
    md.detail = False
    return [f"{i.address:#x}: {i.mnemonic} {i.op_str}".strip() for i in md.disasm(code, va)]

def patch_arm64_elf(
    elf_path: str,
    patches: List[Dict[str, Union[int, str, None]]],
    method: str = "lief",
    out_path: Optional[str] = None,
) -> str:
    if not os.path.isfile(elf_path):
        raise FileNotFoundError(elf_path)

    little = _file_is_little_endian(elf_path)
    binary = lief.parse(elf_path)
    if binary is None:
        raise RuntimeError("LIEF 解析 ELF 失败。")
    mtype = getattr(binary.header, "machine_type", None) or getattr(binary.header, "machine", None)
    if mtype != getattr(lief.ELF.ARCH, "AARCH64", None):
        raise ValueError(f"只支持 AArch64；当前 ELF: {mtype}")

    out_path = out_path or (elf_path + ".debl")

    with open(elf_path, "rb") as f:
        data = bytearray(f.read())
    orig_len = len(data)

    for i, p in enumerate(patches, 1):
        if "addr" not in p or "asm" not in p:
            raise ValueError(f"[{i}] patch 需包含 'addr' 与 'asm'。")
        addr = _norm_addr(p["addr"])
        asm  = str(p["asm"])
        if addr % 4 != 0:
            raise ValueError(f"[{i}] 目标地址 {hex(addr)} 未按 4 字节对齐。")
        max_len = p.get("max_len")
        max_len = int(max_len) if max_len is not None else None

        # 关键：以 addr 作为汇编 PC
        code = _assemble_arm64_at(asm, pc=addr, little_endian=little)
        code = _pad_or_check(code, max_len, little_endian=little)

        off, seg = _va_to_file_off_via_lief(binary, addr)
        seg_off = _seg_fileoff(seg)
        seg_filesz = _seg_filesz(seg)
        seg_end = seg_off + seg_filesz
        if seg_filesz <= 0:
            raise ValueError(f"[{i}] 目标段 p_filesz 无效：{seg_filesz}")
        if not (seg_off <= off and off + len(code) <= seg_end):
            raise ValueError(f"[{i}] 写入超出段 p_filesz：off={off}, len={len(code)}, seg_end={seg_end}")
        if off < 0 or off + len(code) > len(data):
            raise ValueError(f"[{i}] 写入越界：off={off}, len={len(code)}, file_size={len(data)}")

        # 可开调试看看是否正确编码到期望目标：
        # print(f"[dbg] patch@{hex(addr)}:\n  " + "\n  ".join(_disasm_for_sanity(code, addr, little)))

        data[off:off+len(code)] = code

    with open(out_path, "wb") as f:
        f.write(data)

    assert len(data) == orig_len, "文件长度发生改变（只允许覆盖写）。"
    return out_path


def symbolic_execution(project, Br_addr, start_addr, hook_addrs=None, modify_value=None, inspect=False):

    def retn_procedure(state):
        """hook 用：遇到 call/bl 直接‘ret’，防止路径跑飞到库/外部"""
        ip = state.solver.eval(state.regs.ip)
        project.unhook(ip)
        return

    def statement_inspect(state):
        """
        inspect 用：在当前 statement（VEX）为 ITE 时，把 cond 改成 modify_value，
        相当于人为选择 true/false 分支，以探索两条边。
        """
        expressions = list(
            state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            # 只生效一次；注入后清理断点，避免影响后续路径
            state.inspect._breakpoints['statement'] = []

    # 如需 hook 掉函数调用（call/bl/blr），按架构设定跳过长度
    if hook_addrs is not None:
        skip_length = 4      # ARM/ARM64 指令 4 字节


        for hook_addr in hook_addrs:
            project.hook(hook_addr, retn_procedure, length=skip_length)

    # 用 blank_state 从指定地址起步；去掉 LAZY_SOLVES，避免约束延迟求解导致的奇怪路径
    state = project.factory.blank_state(addr=start_addr, remove_options={
                                        angr.sim_options.LAZY_SOLVES})
    if inspect:
        # 在执行前（BP_BEFORE）插入 statement 断点，捕捉 ITE 并改写 cond
        state.inspect.b(
            'statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
    sm = project.factory.simulation_manager(state)

    sm.explore(find=Br_addr)

    if len(sm.found) > 0:
        found = sm.found[0]
        return found.solver.eval(found.regs.x8)

    return None  # 未命中


def handle_br(project, meth_addr = None):
    BR_addr = 0
    hook_addr = []
    num = 0
    cset_addr = 0

    while BR_addr == 0:
        mnemonic = project.factory.block(meth_addr + num, 4).capstone.insns[0].mnemonic
        # print(mnemonic)
        if mnemonic == "bl":
            hook_addr.append(meth_addr + num)

        if mnemonic == "cset":
            cset_addr = meth_addr + num

        if mnemonic == "br":
            BR_addr = meth_addr + num
            break
        if mnemonic == "ret":
            break
        num = num + 4

    if BR_addr == 0:
        print("没有找到 BR 指令")
        return

    if cset_addr == 0:
        print("没有找到 cset 指令")
        ret = symbolic_execution(project, hook_addrs=hook_addr
                                    , start_addr=meth_addr
                                    , Br_addr=BR_addr
                                    , modify_value=claripy.BVV(0, 1)
                                    , inspect=False)
        print(hex(ret))
        my_patches.append({"addr": BR_addr, "asm": f"b {ret:#x}"})


    else:
        print("cset 存在")
        ret = symbolic_execution(project, hook_addrs=hook_addr
                                    , start_addr=meth_addr
                                    , Br_addr=BR_addr
                                    , modify_value=claripy.BVV(0, 1)
                                    , inspect=True)

        print(hex(ret))
        my_patches.append({"addr": BR_addr, "asm": f"b {ret:#x}"})

        ret2 = symbolic_execution(project
                                    , hook_addrs=hook_addr
                                    , start_addr=meth_addr
                                    , Br_addr=BR_addr
                                    , modify_value=claripy.BVV(1, 1), inspect=True)

        print(hex(ret2))
        my_patches.append({"addr": cset_addr, "asm": f"b.ne {ret2:#x}"})

project = angr.Project("C:\\Users\\Administrator\\Desktop\\ollvm\\fla.bl")
handle_addr=[]

meth_addr = 0x238D9C
ret =0
num =0
while ret == 0:
    ins =project.factory.block(meth_addr + num, 4).capstone.insns[0]
    mnemonic = ins.mnemonic
    if mnemonic == "ret":
        ret = ins.address
        break
    if mnemonic == "br":
        handle_addr.append(meth_addr + num +4)
    num = num + 4

handle_addr.append(meth_addr)
for addr in handle_addr:
    print(f"**************************  {hex(addr)}")
    handle_br(project, addr)

elf = r"C:\Users\Administrator\Desktop\ollvm\fla.bl"

out = patch_arm64_elf(
    elf,
    my_patches,
    method="lief",   # 或 "pyelf"
)
print("输出文件：", out)  # C:\...\fla.bl.debl