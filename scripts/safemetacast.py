import idaapi
import idc
import idautils
import re
from collections import defaultdict
safeMetaCast = idc.get_name_ea_simple('__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass')

def is_call_to(e, func):
    return e.op == idaapi.cot_call and e.x.op == idaapi.cot_obj and e.x.obj_ea == func


def demangle(name):
    return idc.demangle_name(name, 0) or idc.demangle_name(re.sub(r'_\d+$', '', name), 0) or name


class SafeMetaCastVisitor(idaapi.ctree_visitor_t):
    def __init__(self):
        super().__init__(idaapi.CV_FAST)
        self.candidates = defaultdict(set)

    def visit_expr(self, expr):
        if expr.op != idaapi.cot_asg:
            return 0

        if expr.x.op != idaapi.cot_var:
            return 0

        call = expr.y
        if not is_call_to(call, safeMetaCast):
            return 0

        if len(call.a) != 2:
            return 0

        arg = call.a[1]
        if arg.op == idaapi.cot_ref:
            arg = arg.x
        if arg.op != idaapi.cot_obj:
            return 0

        self.candidates[expr.x.v.idx].add(arg.obj_ea)
        return 0


def fix_func(ea):
    func = idaapi.decompile(ea)
    visitor = SafeMetaCastVisitor()
    visitor.apply_to(func.body, None)
    fixed = 0
    for lvar_idx, addrs in visitor.candidates.items():
        if len(addrs) != 1:
            continue
        name = demangle(idc.get_name(next(iter(addrs))))
        if not name.endswith('::gMetaClass'):
            continue
        klass = name.split('::', 1)[0]

        ti = idaapi.tinfo_t()
        if idaapi.parse_decl(ti, None, '{}*;'.format(klass), idaapi.PT_SIL) is None:
            print('Unable to parse decl:', '{}*;'.format(klass))
            continue

        lsi = idaapi.lvar_saved_info_t()
        lsi.ll = func.lvars[lvar_idx]
        lsi.type = ti
        if not idaapi.modify_user_lvar_info(ea, idaapi.MLI_TYPE, lsi):
            print('Unable to modify lvar info', hex(ea), hex(lvar_idx))
            continue
        fixed += 1

    print('{}: Fixed {}/{}'.format(idc.get_func_name(ea), fixed, len(visitor.candidates)))


def do_metacast_fix():
    if safeMetaCast == idc.BADADDR:
        print("No safeMetaCast found!")
    func_refs = {idaapi.get_func(ref).start_ea for ref in idautils.CodeRefsTo(safeMetaCast, 1)}
    for addr in func_refs:
        fix_func(addr)
