"""
summary: show decompiler xrefs

description:
  Show decompiler-style Xref when the `Ctrl+X` key is
  pressed in the Decompiler window.

  * supports any global name: functions, strings, integers, ...
  * supports structure member.

author: EiNSTeiN_ (einstein@g3nius.org)
"""
from __future__ import print_function

import ida_kernwin
import ida_hexrays
import ida_typeinf
import ida_idaapi
import ida_struct
import ida_funcs
import idc
import idaapi
import idautils

import traceback
import re

from PyQt5 import QtCore, QtWidgets

XREF_EA = 0
XREF_STRUC_MEMBER = 1

def demangle(name):
    return idc.demangle_name(name, 0) or idc.demangle_name(re.sub(r'_\d+$', '', name), 0) or name


class KextXrefsForm(ida_kernwin.PluginForm):

    def __init__(self, target):

        ida_kernwin.PluginForm.__init__(self)

        self.target = target

        if type(self.target) == ida_hexrays.cexpr_t and self.target.opname in ('memptr', 'memref'):

            self.__type = XREF_STRUC_MEMBER
            name = self.get_struc_name()
            self.__name = 'Kext Xrefs of %s in %s' % (name, idc.get_segm_name(self.target.ea))

        else:
            raise ValueError('cannot show xrefs for this kind of target')

        return

    def get_struc_name(self):

        x = self.target.operands['x']
        m = self.target.operands['m']

        xtype = x.type
        xtype.remove_ptr_or_array()
        typename = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, xtype, '', '')

        sid = ida_struct.get_struc_id(typename)
        sptr = ida_struct.get_struc(sid)
        mid = ida_struct.get_member_id(sptr, m)
        return ida_struct.get_member_fullname(mid) or 'Unknown'

    def OnCreate(self, widget):

        # Get parent widget
        self.parent = self.FormToPyQtWidget(widget)

        self.populate_form()

        return

    def Show(self):
        ida_kernwin.PluginForm.Show(self, self.__name)
        return

    def populate_form(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        layout.addWidget(QtWidgets.QLabel(self.__name))
        self.table = QtWidgets.QTableWidget()
        layout.addWidget(self.table)

        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderItem(0, QtWidgets.QTableWidgetItem("Address"))
        self.table.setHorizontalHeaderItem(1, QtWidgets.QTableWidgetItem("Function"))
        self.table.setHorizontalHeaderItem(2, QtWidgets.QTableWidgetItem("Line"))

        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(2, 450)

        self.table.cellDoubleClicked.connect(self.double_clicked)

        #~ self.table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows )
        self.parent.setLayout(layout)

        self.populate_table()

        return

    def double_clicked(self, row, column):

        ea = self.functionsEA[row]
        idaapi.jumpto(ea)
        #ida_hexrays.open_pseudocode(ea, True) # I prefer to open it in one tab, I might want to check if we already using open_pseudocode

        return

    def get_decompiled_line(self, cfunc, ea):

        print(repr(ea))
        if ea not in cfunc.eamap:
            print('strange, %x is not in %x eamap' % (ea, cfunc.entry_ea))
            return

        insnvec = cfunc.eamap[ea]

        lines = []
        for stmt in insnvec:

            qp = ida_hexrays.qstring_printer_t(cfunc, False)

            stmt._print(0, qp)
            s = qp.s.split('\n')[0]

            #~ s = ida_lines.tag_remove(s)
            lines.append(s)

        return '\n'.join(lines)

    def get_items_for_ea(self, ea):

        frm = [x.frm for x in idautils.XrefsTo(self.__ea)]

        items = []
        for ea in frm:
            try:
                cfunc = ida_hexrays.decompile(ea)

                self.functions.append(cfunc.entry_ea)
                self.functionsEA.append(ea)
                self.items.append((ea, ida_funcs.get_func_name(cfunc.entry_ea) or "", self.get_decompiled_line(cfunc, ea)))

            except Exception as e:
                print('could not decompile: %s' % (str(e), ))
                raise

        return

    def get_items_for_type(self):

        x = self.target.operands['x']
        m = self.target.operands['m']

        xtype = x.type
        xtype.remove_ptr_or_array()
        typename = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, xtype, '', '')

        segment = idaapi.getseg(self.target.ea)

        addresses = []
        for ea in idautils.Functions(segment.start_ea, segment.end_ea):

            try:
                cfunc = ida_hexrays.decompile(ea)
            except:
                print('Decompilation of %x failed' % (ea, ))
                continue

            str(cfunc)

            for citem in cfunc.treeitems:
                citem = citem.to_specific_type
                if not (type(citem) == ida_hexrays.cexpr_t and citem.opname in ('memptr', 'memref')):
                    continue

                _x = citem.operands['x']
                _m = citem.operands['m']
                _xtype = _x.type
                _xtype.remove_ptr_or_array()
                _typename = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, _xtype, '', '')

                if not (_typename == typename and _m == m):
                    continue

                parent = citem
                while parent:
                    if type(parent.to_specific_type) == ida_hexrays.cinsn_t:
                        break
                    parent = cfunc.body.find_parent_of(parent)

                if not parent:
                    print('cannot find parent statement (?!)')
                    continue

                if parent.ea in addresses:
                    continue

                if parent.ea == ida_idaapi.BADADDR:
                    print('parent.ea is BADADDR')
                    continue

                addresses.append(parent.ea)

                self.functions.append(cfunc.entry_ea)
                self.functionsEA.append(parent.ea)
                self.items.append((
                        parent.ea,
                        demangle(ida_funcs.get_func_name(cfunc.entry_ea) or ""),
                        self.get_decompiled_line(cfunc, parent.ea)))


        return []

    def populate_table(self):

        self.functions = []
        self.items = []
        self.functionsEA = []

        if self.__type == XREF_EA:
            self.get_items_for_ea(self.__ea)
        else:
            self.get_items_for_type()

        self.table.setRowCount(len(self.items))

        i = 0
        for item in self.items:
            address, func, line = item
            item = QtWidgets.QTableWidgetItem('0x%x' % (address, ))
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(i, 0, item)
            item = QtWidgets.QTableWidgetItem(func)
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(i, 1, item)
            item = QtWidgets.QTableWidgetItem(line)
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(i, 2, item)

            i += 1

        self.table.resizeRowsToContents()

        return

    def OnClose(self, widget):
        pass


class show_kext_xrefs_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.sel = None

    def activate(self, ctx):
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if not vu or not self.sel:
            print("No vdui? Strange, since this action should be enabled only for pseudocode views.")
            return 0

        form = KextXrefsForm(self.sel)
        form.Show()
        return 1

    def update(self, ctx):
        if ctx.widget_type != ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        vu.get_current_item(ida_hexrays.USE_KEYBOARD)
        item = vu.item
        self.sel = None
        if item.citype == ida_hexrays.VDI_EXPR and item.it.to_specific_type.opname == 'memref':
            # if an expression is selected. verify that it's either a cot_obj, cot_memref or cot_memptr
            self.sel = item.it.to_specific_type

        return ida_kernwin.AST_ENABLE if self.sel else ida_kernwin.AST_DISABLE


class kext_xrefs_hooks_t(ida_hexrays.Hexrays_Hooks):
    def populating_popup(self, widget, phandle, vu):
        ida_kernwin.attach_action_to_popup(widget, phandle, "kextxrefs:show", None)
        return 0


if ida_hexrays.init_hexrays_plugin():
    adesc = ida_kernwin.action_desc_t('kextxrefs:show', 'Show Kext xrefs', show_kext_xrefs_ah_t(), "Ctrl+K")
    if ida_kernwin.register_action(adesc):
        kext_xrefs_hooks = kext_xrefs_hooks_t()
        kext_xrefs_hooks.hook()
    else:
        print("Kext xrefs: Couldn't register action.")
else:
    print('Kext xrefs: hexrays is not available.')
