# -*- coding: utf-8 -*-
# Small deFla (IDA 9.2)
# - 右键函数：写入“函数地址”
# - 右键基本块：设置 序言/主分发器/预分发器、添加/取消真实块、添加/删除探测块
# - 自动寻找结构：推断并写回 UI + 染色（预/主/子分发器、真实/虚假/返回块）
#   且完成后将 “探测块” 内容与 “真实块” 同步一次（变量亦同步）
import os, traceback
import idaapi, ida_kernwin, ida_funcs, ida_bytes, ida_nalt, idc, ida_auto
from idaapi import BADADDR

def defla_patch_a64_exact(elf_path, func_addr, real_black_list, real_black_list_and_ret, ret_black):
    import logging, os, shutil
    import angr
    import claripy
    import lief
    import pyvex
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    import capstone as cs
    from capstone import CsError

    # ---------------- 基本设置：保持你的原始行为 ----------------
    logging.getLogger("angr.storage.memory_mixins.default_filler_mixin").setLevel(logging.ERROR)
    project = angr.Project(elf_path, load_options={"auto_load_libs": False})
    print(f"project base addr: {project.loader.main_object.mapped_base:#x}")

    # ---------------- 你的原始函数们（按原逻辑内联） ----------------
    def scan_bl_sites_a64(project, func_addr: int, *, auto_base: bool = True, build_cfg: bool = True):
        assert project.arch.name.lower().startswith("aarch64"), "仅适配 AArch64"

        def _can_decode(a: int) -> bool:
            try:
                blk = project.factory.block(a, num_inst=1)
                return bool(blk.capstone.insns)
            except Exception:
                return False

        base = getattr(project.loader.main_object, "mapped_base", 0) or 0
        addr = int(func_addr)
        if auto_base and not _can_decode(addr) and base and _can_decode(addr + base):
            addr += base

        func = project.kb.functions.get(addr, None)
        if build_cfg and func is None:
            try:
                project.analyses.CFGFast(normalize=True, function_starts={addr}, symbols=True, force_complete_scan=False)
            except TypeError:
                project.analyses.CFGFast(normalize=True, starts=[addr], symbols=True)
            func = project.kb.functions.get(addr, None)
        if func is None:
            return []

        call_ids = set()
        for name in ("ARM64_INS_BL", "ARM64_INS_BLR", "ARM64_INS_BLRAA", "ARM64_INS_BLRAB", "ARM64_INS_BLRAAZ", "ARM64_INS_BLRABZ"):
            if hasattr(cs.arm64_const, name):
                call_ids.add(getattr(cs.arm64_const, name))

        bl_addrs = set()
        for baddr in list(getattr(func, "block_addrs_set", set())):
            try:
                blk = project.factory.block(baddr)
            except (CsError, Exception):
                continue
            insns = getattr(blk.capstone, "insns", [])
            for insn in insns:
                try:
                    if insn.id in call_ids:
                        bl_addrs.add(int(insn.address))
                except Exception:
                    pass
        return sorted(bl_addrs)

    def symbolic_execution(project, relevant_block_addrs, start_addr,
                           hook_addrs=None, modify_value=None, inspect=False,
                           prologue_addr=None):
        import angr, pyvex, claripy

        def retn_procedure(state):
            ip = state.solver.eval(state.regs.ip)
            project.unhook(ip)
            return

        def statement_inspect(state):
            expressions = list(
                state.scratch.irsb.statements[state.inspect.statement].expressions)
            if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
                state.scratch.temps[expressions[0].cond.tmp] = modify_value
                state.inspect._breakpoints['statement'] = []

        if hook_addrs is not None:
            skip_length = 4
            for hook_addr in hook_addrs:
                project.hook(hook_addr, retn_procedure, length=skip_length)

        if prologue_addr is not None:
            state = project.factory.blank_state(addr=prologue_addr, remove_options={angr.sim_options.LAZY_SOLVES})
            try:
                blk = project.factory.block(int(state.addr))
                succ = project.factory.successors(state, num_inst=len(blk.capstone.insns))
                next_states = list(getattr(succ, "successors", [])) \
                           or list(getattr(succ, "flat_successors", [])) \
                           or list(getattr(succ, "unconstrained_successors", []))
                if next_states:
                    state = next_states[0]
            except Exception:
                pass
            try:
                state.regs.pc = claripy.BVV(int(start_addr), state.arch.bits)
            except Exception:
                try:
                    state.regs.ip = claripy.BVV(int(start_addr), state.arch.bits)
                except Exception:
                    pass
        else:
            state = project.factory.blank_state(addr=start_addr, remove_options={angr.sim_options.LAZY_SOLVES})

        if inspect:
            state.inspect.b('statement',
                            when=angr.state_plugins.inspect.BP_BEFORE,
                            action=statement_inspect)

        sm = project.factory.simulation_manager(state)
        sm.step()
        while len(sm.active) > 0:
            for active_state in sm.active:
                if active_state.addr in relevant_block_addrs:
                    return active_state.addr
            sm.step()
        return None

    def ida_block_has_csel_like_a64(project, addr: int, *,
                                    auto_base: bool = True,
                                    dump_block: bool = False,
                                    return_matches: bool = False,
                                    max_insn: int = 256):
        assert project.arch.name.lower().startswith("aarch64"), "仅适配 AArch64"

        def _can_decode(a: int) -> bool:
            try:
                return bool(project.factory.block(a, num_inst=1).capstone.insns)
            except Exception:
                return False

        base = getattr(project.loader.main_object, "mapped_base", 0) or 0
        cur = int(addr)
        if auto_base and not _can_decode(cur) and base and _can_decode(cur + base):
            cur += base

        want_ids = set()
        want_mnems = {"csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg"}
        if hasattr(cs, "arm64_const"):
            C = cs.arm64_const
            for name in ("ARM64_INS_CSEL", "ARM64_INS_CSINC", "ARM64_INS_CSINV", "ARM64_INS_CSNEG",
                         "ARM64_INS_CSET", "ARM64_INS_CSETM", "ARM64_INS_CINC", "ARM64_INS_CINV", "ARM64_INS_CNEG"):
                if hasattr(C, name):
                    want_ids.add(getattr(C, name))

        def _decode_one(a: int):
            blk = project.factory.block(a, num_inst=1)
            ins = getattr(blk.capstone, "insns", [])
            return ins[0] if ins else None

        def _is_terminator(mnem_lc: str) -> bool:
            if mnem_lc in {"ret", "br"}: return True
            if mnem_lc == "b": return True
            if mnem_lc.startswith("b."): return True
            if mnem_lc in {"cbz", "cbnz", "tbz", "tbnz"}: return True
            return False

        hits, lines, seen = [], [], set()
        for _ in range(int(max_insn)):
            if cur in seen: break
            seen.add(cur)

            insn = _decode_one(cur)
            if not insn:
                lines.append(f"    0x{cur:016X}: <decode fail>")
                break

            m = (insn.mnemonic or "").lower()
            o = (insn.op_str or "").strip()
            text = f"{m} {o}".strip()

            hit = False
            try:
                if want_ids and insn.id in want_ids:
                    hit = True
            except Exception:
                pass
            if not hit and m in want_mnems:
                hit = True
            if hit:
                hits.append((int(insn.address), text))
                tag = "  [CSEL-FAM]"
            else:
                tag = ""

            lines.append(f"    0x{insn.address:016X}: {text}{tag}")

            if _is_terminator(m): break
            cur = int(insn.address) + 4

        if dump_block:
            if lines:
                bb_start = int(lines[0].split(":")[0].split()[-1], 16) if lines[0].startswith("    0x") else cur
                print(f"[IDA-BB @ 0x{bb_start:016X}]  ({len(lines)} insn)")
            for L in lines:
                print(L)

        if return_matches: return (bool(hits), hits)
        return bool(hits)

    # ---------------- 你的主流程：保持逻辑与打印 ----------------
    hook_addrs = scan_bl_sites_a64(project, func_addr)

    first_addr = func_addr  # 入口块地址：用入参代替你代码里的字面量 0x23901C（仅封装，不改算法）
    real_blacks = real_black_list
    check_real_block = real_black_list_and_ret
    ret = ret_black  # 未在逻辑中使用，保持参数占位

    results = {}
    results[first_addr] = {}
    results[first_addr]['has_csel'] = ida_block_has_csel_like_a64(project, first_addr, auto_base=False)
    results[first_addr]['hits'] = []
    if results[first_addr]['has_csel']:
        for val in (1, 0):
            hit = symbolic_execution(
                project,
                relevant_block_addrs=real_blacks,
                start_addr=first_addr,
                hook_addrs=hook_addrs,
                modify_value=claripy.BVV(val, 1),
                inspect=True,
                prologue_addr=first_addr
            )
            results[first_addr]['hits'].append((val, hit))
    else:
        hit = symbolic_execution(
            project,
            relevant_block_addrs=real_blacks,
            start_addr=first_addr,
            hook_addrs=hook_addrs,
            inspect=False,
            prologue_addr=first_addr
        )
        results[first_addr]['hits'].append(('no_csel', hit))

    for addr in real_blacks:
        results[addr] = {}
        results[addr]['has_csel'] = ida_block_has_csel_like_a64(project, addr, auto_base=False)
        results[addr]['hits'] = []
        if results[addr]['has_csel']:
            for val in (1, 0):
                hit = symbolic_execution(
                    project,
                    relevant_block_addrs=real_black_list_and_ret,
                    start_addr=addr,
                    hook_addrs=hook_addrs,
                    modify_value=claripy.BVV(val, 1),
                    inspect=True,
                    prologue_addr=first_addr
                )
                results[addr]['hits'].append((val, hit))
        else:
            hit = symbolic_execution(
                project,
                relevant_block_addrs=real_black_list_and_ret,
                start_addr=addr,
                hook_addrs=hook_addrs,
                inspect=False,
                prologue_addr=first_addr
            )
            results[addr]['hits'].append(('no_csel', hit))

    # ---------------- patch（完全保留你的实现） ----------------
    CSEL_FAM = {"csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg"}
    bin0 = lief.parse(project.filename)
    patched_path = project.filename + ".patched"
    shutil.copy2(project.filename, patched_path)

    KS = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    def assemble_arm64(asm: str, addr: int) -> bytes:
        print(f"[+] Assembling {asm} at 0x{addr:x}...")
        encoding, _ = KS.asm(asm, addr)
        return bytes(encoding)

    def va_to_file_offset(binary: lief.ELF.Binary, va: int) -> int:
        for seg in binary.segments:
            vaddr = int(seg.virtual_address)
            memsz = int(seg.virtual_size)
            off = int(seg.file_offset)
            if vaddr <= va < vaddr + memsz:
                return off + (va - vaddr)
        raise ValueError(f"VA 0x{va:x} not in any PT_LOAD segment")

    def copy_and_patch_bytes(orig_path: str, dst_path: str, file_offset: int, patch_bytes: bytes):
        if not dst_path.endswith(".patched"):
            dst_path = dst_path if dst_path.endswith(".patched") else orig_path + ".patched"
        if not os.path.exists(dst_path):
            shutil.copy2(orig_path, dst_path)
        with open(dst_path, "r+b") as f:
            f.seek(file_offset)
            f.write(patch_bytes)
        return dst_path

    def patch_ins_csel(project, block_addr, address):
        for val, hit in results[block_addr]['hits']:
            if val == 1:
                print(f"  cond=1 -> hit {hit:#x}")
                s = project.factory.block(address, num_inst=1).capstone.insns[0].op_str.split(",")[-1].strip()
                print(project.factory.block(address, num_inst=1).capstone.insns[0])
                beq = assemble_arm64(f"b.{s} 0x{hit:x}", address)
                fo1 = va_to_file_offset(bin0, address)
                copy_and_patch_bytes(project.filename, patched_path, fo1, beq)
            else:
                print(f"  cond=0 -> hit {hit:#x}")
                beq = assemble_arm64(f"b 0x{hit:x}", address + 4)
                fo1 = va_to_file_offset(bin0, address + 4)
                copy_and_patch_bytes(project.filename, patched_path, fo1, beq)
        pass

    def patch_ins_b(project, block_addr, address):
        hit = results[block_addr]['hits'][0][1]
        beq = assemble_arm64(f"b 0x{hit:x}", address)
        fo1 = va_to_file_offset(bin0, address)
        copy_and_patch_bytes(project.filename, patched_path, fo1, beq)

    # 保留你的 fix_addrs 逻辑（仅把入口替换成 func_addr，以便函数可复用）
    fix_addrs ={func_addr}.union(real_black_list)

    for addr in fix_addrs:
        if ida_block_has_csel_like_a64(project, addr, auto_base=False):
            print(f"存在分支 {addr:#x}")
            final_addr = 0
            add = 0
            while final_addr == 0:
                for ins in project.factory.block(addr + add).capstone.insns:
                    if (ins.mnemonic or "").lower() in CSEL_FAM:
                        final_addr = ins.address
                add += len(project.factory.block(addr + add).capstone.insns) * 4
            print(f"找到基本块 csel {final_addr:#x}")
            patch_ins_csel(project, addr, final_addr)
        else:
            print(f"不存在分支 {addr:#x}")
            final_addr = 0
            add = 0
            while final_addr == 0:
                for ins in project.factory.block(addr + add).capstone.insns:
                    if (ins.mnemonic or "").lower() == "b":
                        final_addr = ins.address
                add += len(project.factory.block(addr + add).capstone.insns) * 4
            print(f"找到基本块 b {final_addr:#x}")
            patch_ins_b(project, addr, final_addr)

    return patched_path


















# ---------- Qt 绑定探测 ----------
QT_LIB = None
try:
    from PySide6 import QtWidgets, QtCore, QtGui
    QT_LIB = "PySide6"
except Exception:
    try:
        from PyQt5 import QtWidgets, QtCore, QtGui
        QT_LIB = "PyQt5"
    except Exception:
        QtWidgets = None

# ---------- 自动启动配置 ----------
AUTOSTART = os.environ.get("SMALL_DEFLA_AUTOSTART", "1") != "0"
AUTOSTART_MODE = os.environ.get("SMALL_DEFLA_AUTOSTART_MODE", "open")  # "open" / "open+auto"

# ---------- 插件句柄 + 外部接口 ----------
_SMALL_DEFLA_PLUGIN = None
def small_defla_get_real_blocks(func_ea=None):
    """外部接口：返回真实块集合（EA 升序）。func_ea 为空则取 UI 中函数地址。"""
    try:
        p = _SMALL_DEFLA_PLUGIN
        if not (p and p.form):
            ida_kernwin.warning("Small-defla 未就绪"); return []
        return p.form.get_real_blocks(func_ea)
    except Exception as e:
        ida_kernwin.msg(f"[Small-defla] get_real_blocks error: {e}\n")
        return []

# ---------- 小工具 ----------
def log(msg): ida_kernwin.msg("[Small-defla] " + msg + "\n")
def hexu(x):  return "0x{:X}".format(x) if isinstance(x, int) and x != BADADDR else "-"

def parse_ea(text: str) -> int:
    if not text: return BADADDR
    s = text.strip()
    try:
        if s.lower().startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in s): return int(s, 16)
    except Exception: pass
    try:
        import ida_name
        ea = ida_name.get_name_ea(BADADDR, s)
    except Exception:
        ea = idaapi.get_name_ea(BADADDR, s)
    return ea if ea != BADADDR else BADADDR

def set_font_bold(font, bold=True):
    try: font.setWeight(QtGui.QFont.Weight.Bold if bold else QtGui.QFont.Weight.Normal)
    except Exception:
        try: font.setBold(bold)
        except Exception: pass

def rgb_to_bgr(rgb: int) -> int:
    r = (rgb >> 16) & 0xFF; g = (rgb >> 8) & 0xFF; b = rgb & 0xFF
    return (b << 16) | (g << 8) | r

def color_ea(ea: int, item_color: int = None, line_color: int = None):
    try:
        if item_color is not None: idc.set_color(ea, idc.CIC_ITEM, item_color)
        if line_color is not None: idc.set_color(ea, idc.CIC_LINE, line_color)
    except Exception: pass

DEFCOLOR        = getattr(idc, "DEFCOLOR", 0xFFFFFFFF)
COLOR_PROLOGUE  = rgb_to_bgr(0xE0FFFF)  # LightCyan
COLOR_MAIN_DISP = rgb_to_bgr(0xFFA07A)  # LightSalmon
COLOR_PRE_DISP  = rgb_to_bgr(0x98FB98)  # PaleGreen
COLOR_CLEAR     = DEFCOLOR
COLOR_SUB_DISP  = rgb_to_bgr(0x00BFFF)  # DeepSkyBlue
COLOR_REAL      = rgb_to_bgr(0xFFD700)  # Gold
COLOR_FAKE      = rgb_to_bgr(0xD3D3D3)  # LightGray
COLOR_RET       = rgb_to_bgr(0x9370DB)  # MediumPurple

# ---------- UI ----------
class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form"); Form.resize(643, 520)
        self.label_6   = QtWidgets.QLabel(Form); self.label_6.setGeometry(QtCore.QRect(20, 10, 451, 21))
        self.label     = QtWidgets.QLabel(Form); self.label.setGeometry(QtCore.QRect(30, 40, 54, 12))
        self.firstEdit = QtWidgets.QLineEdit(Form); self.firstEdit.setGeometry(QtCore.QRect(90, 40, 361, 16))
        self.label_2   = QtWidgets.QLabel(Form); self.label_2.setGeometry(QtCore.QRect(30, 70, 54, 12))
        self.mainEdit  = QtWidgets.QLineEdit(Form); self.mainEdit.setGeometry(QtCore.QRect(90, 70, 361, 16))
        self.label_3   = QtWidgets.QLabel(Form); self.label_3.setGeometry(QtCore.QRect(30, 100, 54, 12))
        self.mainnextEdit = QtWidgets.QLineEdit(Form); self.mainnextEdit.setGeometry(QtCore.QRect(90, 100, 361, 16))
        self.label_4   = QtWidgets.QLabel(Form); self.label_4.setGeometry(QtCore.QRect(30, 130, 54, 12))
        self.raelEdit  = QtWidgets.QLineEdit(Form); self.raelEdit.setGeometry(QtCore.QRect(90, 130, 361, 16))
        self.label_5   = QtWidgets.QLabel(Form); self.label_5.setGeometry(QtCore.QRect(30, 160, 54, 12))
        self.preEdit   = QtWidgets.QLineEdit(Form); self.preEdit.setGeometry(QtCore.QRect(90, 160, 361, 16))

        self.label_10  = QtWidgets.QLabel(Form); self.label_10.setGeometry(QtCore.QRect(30, 190, 54, 12))   # 探测块
        self.probeEdit = QtWidgets.QLineEdit(Form); self.probeEdit.setGeometry(QtCore.QRect(90, 190, 361, 16))

        self.label_9   = QtWidgets.QLabel(Form); self.label_9.setGeometry(QtCore.QRect(30, 220, 54, 12))    # 返回块
        self.retEdit   = QtWidgets.QLineEdit(Form); self.retEdit.setGeometry(QtCore.QRect(90, 220, 361, 16))

        self.label_7   = QtWidgets.QLabel(Form); self.label_7.setGeometry(QtCore.QRect(30, 250, 51, 21))
        self.lineEdit  = QtWidgets.QLineEdit(Form); self.lineEdit.setGeometry(QtCore.QRect(90, 250, 271, 21))
        self.autoButton= QtWidgets.QPushButton(Form); self.autoButton.setGeometry(QtCore.QRect(370, 250, 121, 21))

        # —— 合并后的统一按钮
        self.startButton=QtWidgets.QPushButton(Form); self.startButton.setGeometry(QtCore.QRect(30, 285, 150, 24))

        font = QtGui.QFont(); set_font_bold(font, True); self.label_6.setFont(font)
        self.retranslateUi(Form); QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _t = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_t("Form", "Small DeOllvm ----by 看雪论坛 逆天而行"))
        self.label_6.setText(_t("Form", "Small deFla 针对fla 混淆还原辅助工具"))
        self.label.setText(_t("Form", "序言：")); self.label_2.setText(_t("Form", "主分发器："))
        self.label_3.setText(_t("Form", "子分发器：")); self.label_4.setText(_t("Form", "真实块："))
        self.label_5.setText(_t("Form", "预分发器：")); self.label_7.setText(_t("Form", "函数地址："))
        self.label_10.setText(_t("Form", "探测块：")); self.label_9.setText(_t("Form", "返回块："))
        self.autoButton.setText(_t("Form", "自动寻找结构"))
        self.startButton.setText(_t("Form", "开始 fla处理"))

# ---------- 窗体逻辑 ----------
class SmallDeflaForm(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        if QtWidgets is None:
            ida_kernwin.warning("Qt 绑定不可用，降级文本视图"); self._fallback_text_view(); return
        self.parent = self.FormToPyQtWidget(form)
        self.root = QtWidgets.QWidget(self.parent)
        self.ui = Ui_Form(); self.ui.setupUi(self.root)
        lay = QtWidgets.QVBoxLayout(); lay.setContentsMargins(0,0,0,0); lay.addWidget(self.root)
        self.parent.setLayout(lay)

        # 状态
        self._bb_marks = {}  # kind -> (func_entry_ea, bb_start_ea)
        self._auto_marks = {"sub": set(), "real": set(), "fake": set(), "ret": set()}
        self._manual_reals  = {}  # {func_entry_ea: set(bb_start_ea)}
        self._manual_probes = {}  # {func_entry_ea: set(bb_start_ea)}

        # 绑定
        self.ui.autoButton.clicked.connect(self._auto_struct)
        self.ui.startButton.clicked.connect(self._start_fla)         # 合并后的统一入口
        self.ui.lineEdit.returnPressed.connect(self._auto_struct)    # 在函数地址输入框回车 → 自动寻找结构

        # 其余输入框回车 → 启动“开始 fla处理”
        for le in (self.ui.firstEdit, self.ui.mainEdit, self.ui.mainnextEdit,
                   self.ui.raelEdit, self.ui.probeEdit, self.ui.retEdit, self.ui.preEdit):
            le.returnPressed.connect(self._start_fla)

        # UI → 变量 的同步（真实块 / 探测块）
        self.ui.raelEdit.editingFinished.connect(self._on_rael_changed)
        self.ui.probeEdit.editingFinished.connect(self._on_probe_changed)
        self.ui.raelEdit.returnPressed.connect(self._on_rael_changed)
        self.ui.probeEdit.returnPressed.connect(self._on_probe_changed)

    # ----- 手动集合 buckets -----
    def _ensure_bucket(self, dct, func): return dct.setdefault(int(func.start_ea), set())

    # ----- 真实块手动操作 -----
    def set_real_block(self, func, bb_start_ea):
        self._ensure_bucket(self._manual_reals, func).add(int(bb_start_ea))
        lst = set(self._parse_ea_list_text(self.ui.raelEdit.text())); lst.add(int(bb_start_ea))
        self.ui.raelEdit.setText(self._fmt_ea_list_text(sorted(lst)))
        self._color_block(func, bb_start_ea, COLOR_REAL)
        log(f"[Manual] 添加真实块：{hexu(bb_start_ea)}"); ida_kernwin.refresh_idaview_anyway()

    def unset_real_block(self, func, bb_start_ea):
        self._manual_reals.get(int(func.start_ea), set()).discard(int(bb_start_ea))
        lst = [ea for ea in self._parse_ea_list_text(self.ui.raelEdit.text()) if ea != int(bb_start_ea)]
        self.ui.raelEdit.setText(self._fmt_ea_list_text(sorted(lst)))
        mark = (func.start_ea, bb_start_ea)
        if mark in self._auto_marks["real"]: self._color_block(func, bb_start_ea, COLOR_REAL)
        else: self._uncolor_specific_block(func, bb_start_ea)
        log(f"[Manual] 取消真实块：{hexu(bb_start_ea)}"); ida_kernwin.refresh_idaview_anyway()

    def get_real_blocks(self, func_ea: int = None):
        if func_ea is None:
            fn_text = (self.ui.lineEdit.text() or "").strip()
            func_ea = parse_ea(fn_text)
        try: func_ea = int(func_ea)
        except Exception: func_ea = BADADDR
        return sorted(set(self._parse_ea_list_text(self.ui.raelEdit.text())) |
                      set(self._manual_reals.get(func_ea, set())))

    # ----- 探测块手动操作（不着色，仅同步 UI 集合） -----
    def set_probe_block(self, func, bb_start_ea):
        self._ensure_bucket(self._manual_probes, func).add(int(bb_start_ea))
        lst = set(self._parse_ea_list_text(self.ui.probeEdit.text())); lst.add(int(bb_start_ea))
        self.ui.probeEdit.setText(self._fmt_ea_list_text(sorted(lst)))
        log(f"[Manual] 添加探测块：{hexu(bb_start_ea)}")

    def unset_probe_block(self, func, bb_start_ea):
        self._manual_probes.get(int(func.start_ea), set()).discard(int(bb_start_ea))
        lst = [ea for ea in self._parse_ea_list_text(self.ui.probeEdit.text()) if ea != int(bb_start_ea)]
        self.ui.probeEdit.setText(self._fmt_ea_list_text(sorted(lst)))
        log(f"[Manual] 删除探测块：{hexu(bb_start_ea)}")

    # ----- UI 变更 → 变量存储 -----
    def _on_rael_changed(self):
        """把 UI 中的真实块写回 _manual_reals；对新增/删除手动真实块同步上/去色。"""
        try:
            func_ea = parse_ea((self.ui.lineEdit.text() or "").strip())
            f = ida_funcs.get_func(func_ea)
            if not f: return
            fea = int(f.start_ea)
            ui_reals = set(self._parse_ea_list_text(self.ui.raelEdit.text()))
            auto_reals = {bb for fe, bb in self._auto_marks["real"] if int(fe) == fea}
            new_manual = {int(x) for x in ui_reals if int(x) not in auto_reals}
            old_manual = set(self._manual_reals.get(fea, set()))
            self._manual_reals[fea] = set(new_manual)
            added, removed = new_manual - old_manual, old_manual - new_manual
            for ea in added:   self._color_block(f, ea, COLOR_REAL)
            for ea in removed:
                if ea not in auto_reals: self._uncolor_specific_block(f, ea)
            self.ui.raelEdit.setText(self._fmt_ea_list_text(sorted(ui_reals)))
            ida_kernwin.refresh_idaview_anyway()
            log(f"[Sync] UI→变量：真实块 手动={len(new_manual)}(added {len(added)}, removed {len(removed)})")
        except Exception as e:
            ida_kernwin.warning(f"Sync real blocks error: {e}\n{traceback.format_exc()}")

    def _on_probe_changed(self):
        """把 UI 中的探测块写回 _manual_probes（不着色）。"""
        try:
            func_ea = parse_ea((self.ui.lineEdit.text() or "").strip())
            f = ida_funcs.get_func(func_ea)
            if not f: return
            fea = int(f.start_ea)
            ui_probes = set(self._parse_ea_list_text(self.ui.probeEdit.text()))
            self._manual_probes[fea] = set(int(x) for x in ui_probes)
            self.ui.probeEdit.setText(self._fmt_ea_list_text(sorted(ui_probes)))
            log(f"[Sync] UI→变量：探测块 = {len(ui_probes)}")
        except Exception as e:
            ida_kernwin.warning(f"Sync probe blocks error: {e}\n{traceback.format_exc()}")

    # ----- 显示/解析数组 -----
    def _fmt_ea_list_text(self, eas): return "" if not eas else "[" + ", ".join(hexu(ea) for ea in eas) + "]"
    def _parse_ea_list_text(self, text):
        if not text: return []
        s = text.strip();  s = s[1:-1] if s.startswith("[") and s.endswith("]") else s
        import re
        return [int(h,16) for h in re.findall(r"0x[0-9A-Fa-f]+", s)]

    # ----- 批量着色记录 -----
    def _apply_auto_color(self, func, blocks, color, mark_key):
        for bb in blocks:
            try:
                self._color_block(func, bb.start_ea, color)
                self._auto_marks[mark_key].add((func.start_ea, bb.start_ea))
            except Exception: pass

    # ----- 指令/块工具 -----
    def _block_last_mnem(self, bb) -> str:
        try:
            last = ida_bytes.prev_head(bb.end_ea, bb.start_ea)
            m = idc.print_insn_mnem(last) or ""
            return m.strip().upper()
        except Exception:
            return ""
    def _ends_with_uncond_B(self, bb) -> bool: return self._block_last_mnem(bb) == "B"

    # ----- 自动寻找结构 -----
    def _auto_struct(self):
        try:
            fn_text = (self.ui.lineEdit.text() or "").strip()
            if not fn_text: ida_kernwin.warning("请先填写函数地址/符号名"); return
            func_ea = parse_ea(fn_text); func = ida_funcs.get_func(func_ea)
            if func_ea == BADADDR or not func: ida_kernwin.warning("函数地址解析失败"); return

            # 兼容版 switch 统计
            def _compat_get_switch_info(ea):
                for mod, name in ((ida_nalt,"get_switch_info_ex"),(ida_nalt,"get_switch_info"),
                                  (idaapi,"get_switch_info_ex"),(idaapi,"get_switch_info")):
                    try:
                        fn = getattr(mod, name, None)
                        if fn:
                            si = fn(ea)
                            if si: return si
                    except Exception: pass
                return None
            def _compat_casevec_t():
                for mod in (ida_nalt, idaapi):
                    cv = getattr(mod, "casevec_t", None)
                    if cv: return cv
                return None
            def _compat_calc_switch_cases(ea, vec):
                for mod in (ida_nalt, idaapi):
                    fn = getattr(mod, "calc_switch_cases", None)
                    if fn:
                        try: return bool(fn(ea, vec))
                        except Exception: pass
                return False
            def _count_switch_cases_in_block(bb):
                ea = bb.start_ea
                while ea < bb.end_ea:
                    si = _compat_get_switch_info(ea)
                    if si:
                        CV = _compat_casevec_t()
                        if CV:
                            vec = CV()
                            if _compat_calc_switch_cases(ea, vec):
                                cnt = 0
                                for c in vec:
                                    t = getattr(c, "targets", [])
                                    try: cnt += len(list(t))
                                    except Exception:
                                        try: cnt += len(t)
                                        except Exception: pass
                                return cnt
                    ea = ida_bytes.next_head(ea, bb.end_ea)
                return 0

            self._clear_auto_colors()
            fclist = [b for b in idaapi.FlowChart(func)]
            if not fclist: ida_kernwin.warning("该函数没有 FlowChart"); return
            entry_bb = next((b for b in fclist if b.start_ea <= func.start_ea < b.end_ea), fclist[0])

            # 预分发器：入度最大（优先非入口）
            pre_bb, best_deg = entry_bb, -1
            for b in fclist:
                indeg = len(list(b.preds()))
                if (indeg > best_deg) or (indeg == best_deg and pre_bb is entry_bb and b is not entry_bb):
                    pre_bb, best_deg = b, indeg

            succs = list(pre_bb.succs())
            if not succs: ida_kernwin.warning("预分发器无后继，无法确定分发器"); return

            def disp_key(bb): return (_count_switch_cases_in_block(bb), len(list(bb.succs())))
            succs_sorted = sorted(succs, key=disp_key, reverse=True)
            main_disp = succs_sorted[0]

            # UI 三点回填 + 着色
            self.apply_block_selection("prologue", func, entry_bb.start_ea)
            self.apply_block_selection("pre",       func, pre_bb.start_ea)
            self.apply_block_selection("main",      func, main_disp.start_ea)

            # 子分发器
            def _unique_sort_by_ea(bbs):
                seen, out = set(), []
                for b in bbs:
                    ea = int(b.start_ea)
                    if ea not in seen: seen.add(ea); out.append(b)
                out.sort(key=lambda x: int(x.start_ea)); return out
            sub_disp_list = []
            for bb in succs_sorted[1:]:
                c, o = disp_key(bb)
                if c >= 1 or o >= 2: sub_disp_list.append(bb)
            sub_disp_list = _unique_sort_by_ea(sub_disp_list)

            # 返回块：无后继
            ret_blocks = _unique_sort_by_ea([b for b in fclist if len(list(b.succs())) == 0])

            # 真实块候选：预分发器前驱，末指令==B；排除特殊块
            exclude = {int(entry_bb.start_ea), int(pre_bb.start_ea), int(main_disp.start_ea)}
            exclude.update(int(b.start_ea) for b in sub_disp_list)
            exclude.update(int(b.start_ea) for b in ret_blocks)
            real_blocks = _unique_sort_by_ea([b for b in pre_bb.preds()
                                              if int(b.start_ea) not in exclude and self._ends_with_uncond_B(b)])
            # 虚假块：其余
            special = set(exclude) | {int(b.start_ea) for b in real_blocks}
            fake_blocks = _unique_sort_by_ea([b for b in fclist if int(b.start_ea) not in special])

            # 写回 UI
            self.ui.mainnextEdit.setText(self._fmt_ea_list_text([b.start_ea for b in sub_disp_list]))
            manual_real = self._manual_reals.get(int(func.start_ea), set())
            merged_real = sorted(set(int(b.start_ea) for b in real_blocks) | set(manual_real))
            self.ui.raelEdit.setText(self._fmt_ea_list_text(merged_real))
            self.ui.retEdit.setText(self._fmt_ea_list_text([b.start_ea for b in ret_blocks]))

            # —— 同步一次：“探测块” = 当前“真实块”（UI + 变量）
            self.ui.probeEdit.setText(self._fmt_ea_list_text(merged_real))
            self._manual_probes[int(func.start_ea)] = set(merged_real)

            # 着色
            self._apply_auto_color(func, sub_disp_list, COLOR_SUB_DISP, "sub")
            self._apply_auto_color(func, real_blocks,  COLOR_REAL,      "real")
            self._apply_auto_color(func, fake_blocks,  COLOR_FAKE,      "fake")
            self._apply_auto_color(func, ret_blocks,   COLOR_RET,       "ret")
            # 手动真实块也保持金色
            for rea in manual_real:
                for b in fclist:
                    if int(b.start_ea) == int(rea):
                        self._color_block(func, b.start_ea, COLOR_REAL); break

            ida_kernwin.refresh_idaview_anyway()
            def _fmt_list(blks): return [hexu(b.start_ea) for b in blks]
            log(f"[Auto] 预分发器:{hexu(pre_bb.start_ea)} | 主分发器:{hexu(main_disp.start_ea)}")
            log(f"[Auto] 子分发器:{_fmt_list(sub_disp_list)} | 返回块:{_fmt_list(ret_blocks)}")
            log(f"[Auto] 真实块:{_fmt_list(real_blocks)} | 虚假块数:{len(fake_blocks)} | 函数:{func.name}")
            ida_kernwin.info("自动寻找结构完成（探测块已与真实块同步）")
        except Exception as e:
            ida_kernwin.warning(f"Auto struct error: {e}\n{traceback.format_exc()}")

    # ----- “开始 fla处理”：收集参数并传入空方法 -----
    def _start_fla(self):
        try:
            # 1) 路径
            input_path = ""
            for getter in (
                lambda: ida_nalt.get_input_file_path(),
                lambda: idaapi.get_input_file_path(),
                lambda: idc.GetInputFilePath() if hasattr(idc, "GetInputFilePath") else ""
            ):
                try:
                    p = getter()
                    if p: input_path = p; break
                except Exception: pass

            # 2) 地址/数组
            prologue_ea  = parse_ea(self.ui.firstEdit.text())
            main_disp_ea = parse_ea(self.ui.mainEdit.text())

            real_blocks  = self._parse_ea_list_text(self.ui.raelEdit.text())
            probe_blocks = self._parse_ea_list_text(self.ui.probeEdit.text())

            ret_list     = self._parse_ea_list_text(self.ui.retEdit.text())
            ret_bb_ea    = ret_list[0] if ret_list else BADADDR  # 取一个返回块地址（无则 BADADDR）

            # 传入“空方法”供你实现
            self._on_fla_start(
                input_path=input_path,
                real_blocks=sorted(set(int(x) for x in real_blocks)),
                probe_blocks=sorted(set(int(x) for x in probe_blocks)),
                ret_bb_ea=int(ret_bb_ea) if ret_bb_ea != BADADDR else BADADDR,
                prologue_ea=int(prologue_ea) if prologue_ea != BADADDR else BADADDR,
                main_disp_ea=int(main_disp_ea) if main_disp_ea != BADADDR else BADADDR
            )
            ida_kernwin.info("已触发：开始 fla处理（参数已传入 _on_fla_start）")
        except Exception as e:
            ida_kernwin.warning(f"start_fla error: {e}\n{traceback.format_exc()}")

    def _on_fla_start(self, input_path, real_blocks, probe_blocks, ret_bb_ea, prologue_ea, main_disp_ea):
        """
        这里留空，方便你自行实现。
        参数:
            input_path (str): IDA 当前解析文件的路径
            real_blocks (List[int]): 真实块起始地址数组（升序，去重）
            probe_blocks (List[int]): 探测块起始地址数组（升序，去重）
            ret_bb_ea (int): 一个返回块的起始地址（若找不到则 BADADDR）
            prologue_ea (int): 序言块起始地址
            main_disp_ea (int): 主分发器块起始地址
        """
        # TODO: 在此处实现你的 FLA 处理逻辑
        log(f"[FLA] path={input_path}\n      real={list(map(hexu, real_blocks))}\n"
            f"      probe={list(map(hexu, probe_blocks))}\n      ret={hexu(ret_bb_ea)} "
            f"prologue={hexu(prologue_ea)} main={hexu(main_disp_ea)}")


        # ret = defla_ollvm_fla_a64(
        #     elf_path=r"C:\Users\Administrator\Desktop\ollvm\fla.static",
        #     fun_addr=0x23901C,
        #     real_black_list={0x2390C0, 0x239148, 0x2390F4},
        #     real_black_list_and_ret={0x2390C0, 0x239148, 0x2390F4, 0x239158, 0x239134, 0x239140},
        #     prologue_addr=0x23901C,
        #     detect_mode="conservative",  # 或 "aggressive"
        #     debug=True
        # )

        ret = defla_patch_a64_exact(
            elf_path = input_path,
            func_addr = prologue_ea,
            real_black_list_and_ret=probe_blocks,
            real_black_list =real_blocks ,
            ret_black=ret_bb_ea
        )
        log(f"[FLA] 结果:{ret}")

        pass

    # ----- 选中并上色 -----
    def apply_block_selection(self, kind: str, func, bb_start_ea: int):
        color = {"prologue": COLOR_PROLOGUE, "main": COLOR_MAIN_DISP, "pre": COLOR_PRE_DISP}.get(kind)
        if color is None: return
        {"prologue": self.ui.firstEdit, "main": self.ui.mainEdit, "pre": self.ui.preEdit}[kind].setText(hexu(bb_start_ea))
        self._uncolor_old(kind); self._color_block(func, bb_start_ea, color)
        self._bb_marks[kind] = (func.start_ea, bb_start_ea); log(f"设置 {kind}: {hexu(bb_start_ea)} 并已上色")

    def _find_block(self, func, bb_start_ea):
        for b in idaapi.FlowChart(func):
            if b.start_ea == bb_start_ea: return b
        return None

    def _color_block(self, func, bb_start_ea: int, color: int):
        try:
            blk = self._find_block(func, bb_start_ea)
            if not blk: return
            ea = blk.start_ea
            while ea < blk.end_ea:
                color_ea(ea, item_color=color, line_color=color)
                ea = ida_bytes.next_head(ea, blk.end_ea)
            try:
                import ida_graph
                ni = ida_graph.node_info_t(); ni.bg_color = color
                ida_graph.set_node_info2(func.start_ea, blk.id, ni, ida_graph.NIF_BG_COLOR)
            except Exception: pass
            ida_kernwin.refresh_idaview_anyway()
        except Exception as e:
            ida_kernwin.warning(f"Color block error: {e}\n{traceback.format_exc()}")

    def _uncolor_old(self, kind: str):
        mark = self._bb_marks.get(kind)
        if not mark: return
        func = ida_funcs.get_func(mark[0]);  bb_start = mark[1]
        if not func: return
        self._uncolor_specific_block(func, bb_start)

    def _clear_auto_colors(self):
        for kind in ("sub","real","fake","ret"):
            for func_entry, bb_start in list(self._auto_marks[kind]):
                f = ida_funcs.get_func(func_entry)
                if f: self._uncolor_specific_block(f, bb_start)
            self._auto_marks[kind].clear()
        ida_kernwin.refresh_idaview_anyway()

    def _uncolor_specific_block(self, func, bb_start_ea: int):
        try:
            blk = self._find_block(func, bb_start_ea)
            if not blk: return
            ea = blk.start_ea
            while ea < blk.end_ea:
                color_ea(ea, item_color=COLOR_CLEAR, line_color=COLOR_CLEAR)
                ea = ida_bytes.next_head(ea, blk.end_ea)
            try:
                import ida_graph
                ni = ida_graph.node_info_t(); ni.reset()
                ida_graph.set_node_info2(func.start_ea, blk.id, ni, ida_graph.NIF_BG_COLOR)
            except Exception: pass
        except Exception: pass

    def _fallback_text_view(self):
        class _Text(ida_kernwin.simplecustviewer_t):
            def Create(self2, title):
                if not super().Create(title): return False
                self2.AddLine("Small-defla (text mode)")
                self2.AddLine("Qt 绑定不可用，展示降级文本视图。")
                self2.AddLine("在函数内按 Alt-Shift-Z 再试。"); return True
        self.tv = _Text(); self.tv.Create("Small-defla"); self.tv.Show()

# ---------- 右键菜单 Hook ----------
class _PopupHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin): super().__init__(); self.plugin = plugin
    def finish_populating_widget_popup(self, widget, popup_handle):
        wt = ida_kernwin.get_widget_type(widget)
        if wt in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE, ida_kernwin.BWN_FUNCS):
            ida_kernwin.attach_action_to_popup(widget, popup_handle, self.plugin.ACTION_PICK_FUNC, "Small deOllvm/")
        if wt in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
            for act in (self.plugin.ACTION_SET_PROLOGUE, self.plugin.ACTION_SET_MAIN, self.plugin.ACTION_SET_PRE,
                        self.plugin.ACTION_ADD_REAL, self.plugin.ACTION_CLR_REAL,
                        self.plugin.ACTION_ADD_PROBE, self.plugin.ACTION_CLR_PROBE):
                ida_kernwin.attach_action_to_popup(widget, popup_handle, act, "Small deOllvm/")
        return 0

# ---------- 自动启动 Hook ----------
class _BootHook(ida_kernwin.UI_Hooks):
    def __init__(self, plugin): super().__init__(); self.plugin = plugin; self._done = False
    def ready_to_run(self):
        if self._done or not AUTOSTART: return 0
        self._done = True
        def _do():
            try: ida_auto.auto_wait()
            except Exception: pass
            try:
                self.plugin._open_form()
                if AUTOSTART_MODE == "open+auto" and self.plugin.form is not None:
                    fea = self.plugin._get_func_ea_from_context()
                    if fea != BADADDR:
                        self.plugin.form.ui.lineEdit.setText(hexu(fea))
                        try: self.plugin.form._auto_struct()
                        except Exception: pass
            except Exception as e:
                ida_kernwin.msg(f"[Small-defla] autostart error: {e}\n")
        idaapi.execute_sync(_do, idaapi.MFF_FAST); return 0

# ---------- 插件入口 ----------
class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "对 OLLVM 进行还原（IDA 9.2）"
    help = "Small-deFla UI"
    wanted_name = "Small-defla (测试)"
    wanted_hotkey = "Alt-Shift-Z"

    ACTION_MAIN_UI      = "small:defla.ui"
    ACTION_PICK_FUNC    = "small:defla.pickfunc"
    ACTION_SET_PROLOGUE = "small:defla.set_prologue"
    ACTION_SET_MAIN     = "small:defla.set_main"
    ACTION_SET_PRE      = "small:defla.set_pre"
    ACTION_ADD_REAL     = "small:defla.add_real"
    ACTION_CLR_REAL     = "small:defla.clr_real"
    ACTION_ADD_PROBE    = "small:defla.add_probe"
    ACTION_CLR_PROBE    = "small:defla.clr_probe"

    def init(self):
        log(f"init() | Qt={QT_LIB}")
        self.form = None
        self._install_actions_and_menu()
        self._ui_hooks = _PopupHooks(self); self._ui_hooks.hook()
        self._boot_hook = _BootHook(self);  self._boot_hook.hook()
        global _SMALL_DEFLA_PLUGIN; _SMALL_DEFLA_PLUGIN = self
        return idaapi.PLUGIN_OK

    def run(self, arg): log("run()"); self._open_form()

    def term(self):
        log("term()")
        try:
            if getattr(self, "_ui_hooks", None):  self._ui_hooks.unhook()
        except Exception: pass
        try:
            if getattr(self, "_boot_hook", None): self._boot_hook.unhook()
        except Exception: pass
        self._uninstall_actions_and_menu()
        global _SMALL_DEFLA_PLUGIN; _SMALL_DEFLA_PLUGIN = None

    # ----- 打开窗体 -----
    def _open_form(self):
        try:
            if self.form is None: self.form = SmallDeflaForm()
            self.form.Show("Small-defla UI", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        except Exception as e:
            ida_kernwin.warning(f"Open form failed: {e}\n{traceback.format_exc()}")

    # ----- 注册动作 & 菜单 -----
    def _install_actions_and_menu(self):
        outer = self
        def _reg(action, text, handler, hotkey=None, tooltip=""):
            try: ida_kernwin.unregister_action(action)
            except Exception: pass
            ida_kernwin.register_action(ida_kernwin.action_desc_t(action, text, handler, hotkey, tooltip, -1))

        class HOpen(ida_kernwin.action_handler_t):
            def activate(self, ctx): outer._open_form(); return 1
            def update(self, ctx):   return ida_kernwin.AST_ENABLE_ALWAYS
        _reg(self.ACTION_MAIN_UI, "Small-defla", HOpen(), "Alt-Shift-Z", "Open Small-defla UI")
        if not ida_kernwin.attach_action_to_menu("Edit/Small-defla", self.ACTION_MAIN_UI, ida_kernwin.SETMENU_APP):
            ida_kernwin.attach_action_to_menu("Edit/Plugins/Small-defla", self.ACTION_MAIN_UI, ida_kernwin.SETMENU_APP)

        class HPickFunc(ida_kernwin.action_handler_t):
            def activate(self, ctx):
                ea = outer._get_func_ea_from_context()
                if ea == BADADDR: ida_kernwin.warning("未能获取函数地址"); return 0
                outer._open_form(); outer.form.ui.lineEdit.setText(hexu(ea))
                log(f"选择函数: {hexu(ea)} → 已写入 UI"); return 1
            def update(self, ctx):
                return ida_kernwin.AST_ENABLE_FOR_WIDGET if outer._get_func_ea_from_context()!=BADADDR else ida_kernwin.AST_DISABLE
        _reg(self.ACTION_PICK_FUNC, "选择该函数", HPickFunc(), None, "写入函数地址")

        # 生成“标记为序言/主/预”的动作
        def _mk_block_action(action_name, title_text, kind):
            class H(ida_kernwin.action_handler_t):
                def activate(self, ctx):
                    func, bb = outer._get_block_from_context()
                    if not func or bb == BADADDR: ida_kernwin.warning("未能获取基本块"); return 0
                    outer._open_form(); outer.form.apply_block_selection(kind, func, bb); return 1
                def update(self, ctx):
                    f, b = outer._get_block_from_context()
                    return ida_kernwin.AST_ENABLE_FOR_WIDGET if f and b!=BADADDR else ida_kernwin.AST_DISABLE
            _reg(action_name, title_text, H(), None, f"将当前基本块标记为{title_text}")
        _mk_block_action(self.ACTION_SET_PROLOGUE, "设置为序言", "prologue")
        _mk_block_action(self.ACTION_SET_MAIN,     "设置为主分发器", "main")
        _mk_block_action(self.ACTION_SET_PRE,      "设置为预分发器", "pre")

        # 添加/取消真实块
        class HAddReal(ida_kernwin.action_handler_t):
            def activate(self, ctx):
                func, bb = outer._get_block_from_context()
                if not func or bb == BADADDR: ida_kernwin.warning("未能获取基本块"); return 0
                outer._open_form(); outer.form.set_real_block(func, bb); return 1
            def update(self, ctx):
                f, b = outer._get_block_from_context()
                return ida_kernwin.AST_ENABLE_FOR_WIDGET if f and b!=BADADDR else ida_kernwin.AST_DISABLE
        _reg(self.ACTION_ADD_REAL, "添加到真实块并着色", HAddReal(), None, "加入真实块集合")

        class HClrReal(ida_kernwin.action_handler_t):
            def activate(self, ctx):
                func, bb = outer._get_block_from_context()
                if not func or bb == BADADDR: ida_kernwin.warning("未能获取基本块"); return 0
                outer._open_form(); outer.form.unset_real_block(func, bb); return 1
            def update(self, ctx):
                f, b = outer._get_block_from_context()
                return ida_kernwin.AST_ENABLE_FOR_WIDGET if f and b!=BADADDR else ida_kernwin.AST_DISABLE
        _reg(self.ACTION_CLR_REAL, "取消设置真实块并着色", HClrReal(), None, "从真实块集合移除")

        # 添加/删除探测块（不着色）
        class HAddProbe(ida_kernwin.action_handler_t):
            def activate(self, ctx):
                func, bb = outer._get_block_from_context()
                if not func or bb == BADADDR: ida_kernwin.warning("未能获取基本块"); return 0
                outer._open_form(); outer.form.set_probe_block(func, bb); return 1
            def update(self, ctx):
                f, b = outer._get_block_from_context()
                return ida_kernwin.AST_ENABLE_FOR_WIDGET if f and b!=BADADDR else ida_kernwin.AST_DISABLE
        _reg(self.ACTION_ADD_PROBE, "添加到探测块", HAddProbe(), None, "加入探测块集合")

        class HClrProbe(ida_kernwin.action_handler_t):
            def activate(self, ctx):
                func, bb = outer._get_block_from_context()
                if not func or bb == BADADDR: ida_kernwin.warning("未能获取基本块"); return 0
                outer._open_form(); outer.form.unset_probe_block(func, bb); return 1
            def update(self, ctx):
                f, b = outer._get_block_from_context()
                return ida_kernwin.AST_ENABLE_FOR_WIDGET if f and b!=BADADDR else ida_kernwin.AST_DISABLE
        _reg(self.ACTION_CLR_PROBE, "删除探测块", HClrProbe(), None, "从探测块集合移除")

    def _uninstall_actions_and_menu(self):
        for path in ("Edit/Small-defla", "Edit/Plugins/Small-defla"):
            try: ida_kernwin.detach_action_from_menu(path, self.ACTION_MAIN_UI)
            except Exception: pass
        for act in (self.ACTION_MAIN_UI, self.ACTION_PICK_FUNC,
                    self.ACTION_SET_PROLOGUE, self.ACTION_SET_MAIN, self.ACTION_SET_PRE,
                    self.ACTION_ADD_REAL, self.ACTION_CLR_REAL,
                    self.ACTION_ADD_PROBE, self.ACTION_CLR_PROBE):
            try: ida_kernwin.unregister_action(act)
            except Exception: pass

    # ----- 取函数/基本块 -----
    def _get_func_ea_from_context(self):
        try:
            w = ida_kernwin.get_current_widget()
            if not w:
                ea = ida_kernwin.get_screen_ea(); f = ida_funcs.get_func(ea)
                return f.start_ea if f else BADADDR
            wt = ida_kernwin.get_widget_type(w)
            if wt == ida_kernwin.BWN_PSEUDOCODE:
                try:
                    import ida_hexrays as hx
                    vdui = hx.get_widget_vdui(w)
                    if vdui and vdui.cfunc: return vdui.cfunc.entry_ea
                except Exception: pass
            if wt == ida_kernwin.BWN_DISASM:
                ea = ida_kernwin.get_screen_ea(); f = ida_funcs.get_func(ea)
                if f: return f.start_ea
            if wt == ida_kernwin.BWN_FUNCS:
                vu = ida_kernwin.get_current_viewer()
                try:
                    res = ida_kernwin.get_highlight(vu); ident = None
                    if isinstance(res, tuple) and res and res[0]:
                        data = res[1] if len(res)>1 else None
                        ident = data if isinstance(data, str) else getattr(data, "text", None) or (data[0] if isinstance(data,(tuple,list)) and data else None)
                    if ident:
                        try:
                            import ida_name
                            pea = ida_name.get_name_ea(BADADDR, ident)
                        except Exception:
                            pea = idaapi.get_name_ea(BADADDR, ident)
                        f = ida_funcs.get_func(pea)
                        if f: return f.start_ea
                except Exception: pass
            ea = ida_kernwin.get_screen_ea(); f = ida_funcs.get_func(ea)
            return f.start_ea if f else BADADDR
        except Exception:
            return BADADDR

    def _get_block_from_context(self):
        try:
            w = ida_kernwin.get_current_widget(); wt = ida_kernwin.get_widget_type(w); ea = BADADDR
            if wt == ida_kernwin.BWN_PSEUDOCODE:
                try:
                    import ida_hexrays as hx
                    vdui = hx.get_widget_vdui(w)
                    if vdui and vdui.cfunc: ea = vdui.cfunc.get_ea(vdui.cpos)
                except Exception: ea = ida_kernwin.get_screen_ea()
            else: ea = ida_kernwin.get_screen_ea()
            f = ida_funcs.get_func(ea)
            if not f: return (None, BADADDR)
            for b in idaapi.FlowChart(f):
                if b.start_ea <= ea < b.end_ea: return (f, b.start_ea)
            return (f, BADADDR)
        except Exception:
            return (None, BADADDR)

def PLUGIN_ENTRY():
    log("PLUGIN_ENTRY()")
    return MyPlugin()
