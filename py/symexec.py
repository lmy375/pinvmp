from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container

from miasm2.ir.symbexec import SymbolicExecutionEngine

from miasm2.arch.x86.sem import ir_x86_32
from miasm2.arch.x86 import regs
from miasm2.arch.x86.regs import *

from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp

from miasm2.core import asmblock
from miasm2.ir.translators import Translator


####################################

# patch shift

def patch_shift_rotate():
    import miasm2.expression.expression as m2_expr
    from miasm2.expression.simplifications import expr_simp
    from miasm2.arch.x86.arch import mn_x86, repeat_mn, replace_regs
    from miasm2.expression.expression_helper import expr_cmps, expr_cmpu
    import miasm2.arch.x86.regs as regs
    from miasm2.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock

    import  miasm2.arch.x86.sem
    get_shift = miasm2.arch.x86.sem.get_shift
    update_flag_znp = miasm2.arch.x86.sem.update_flag_znp

    def patch_shift_tpl(op, ir, instr, a, b, c=None, op_inv=None, left=False,
               custom_of=None):
        # assert c is not None
        if c is not None:
            shifter = get_shift(a, c)
        else:
            shifter = get_shift(a, b)

        res = m2_expr.ExprOp(op, a, shifter)
        cf_from_dst = m2_expr.ExprOp(op, a,
                                     (shifter - m2_expr.ExprInt(1, a.size)))
        cf_from_dst = cf_from_dst.msb() if left else cf_from_dst[:1]

        new_cf = cf_from_dst
        i1 = m2_expr.ExprInt(1, size=a.size)
        if c is not None:
            # There is a source for new bits
            isize = m2_expr.ExprInt(a.size, size=a.size)
            mask = m2_expr.ExprOp(op_inv, i1, (isize - shifter)) - i1

            # An overflow can occured, emulate the 'undefined behavior'
            # Overflow behavior if (shift / size % 2)
            base_cond_overflow = c if left else (
                c - m2_expr.ExprInt(1, size=c.size))
            cond_overflow = base_cond_overflow & m2_expr.ExprInt(a.size, c.size)
            if left:
                # Overflow occurs one round before right
                mask = m2_expr.ExprCond(cond_overflow, mask, ~mask)
            else:
                mask = m2_expr.ExprCond(cond_overflow, ~mask, mask)

            # Build res with dst and src
            res = ((m2_expr.ExprOp(op, a, shifter) & mask) |
                   (m2_expr.ExprOp(op_inv, b, (isize - shifter)) & ~mask))

            # Overflow case: cf come from src (bit number shifter % size)
            cf_from_src = m2_expr.ExprOp(op, b,
                                         (c.zeroExtend(b.size) &
                                          m2_expr.ExprInt(a.size - 1, b.size)) - i1)
            cf_from_src = cf_from_src.msb() if left else cf_from_src[:1]
            new_cf = m2_expr.ExprCond(cond_overflow, cf_from_src, cf_from_dst)

        # Overflow flag, only occured when shifter is equal to 1
        if custom_of is None:
            value_of = a.msb() ^ a[-2:-1] if left else b[:1] ^ a.msb()
        else:
            value_of = custom_of

        # Build basic blocks
        e_do = [
            m2_expr.ExprAff(regs.cf, new_cf),
            m2_expr.ExprAff(regs.of, m2_expr.ExprCond(shifter - i1,
                                                 m2_expr.ExprInt(0, regs.of.size),
                                                 value_of)),
            m2_expr.ExprAff(a, res),
        ]
        e_do += update_flag_znp(res)

        return (e_do, [])

    miasm2.arch.x86.sem._shift_tpl = patch_shift_tpl



    def patch_rotate_tpl(ir, instr, dst, src, op, left=False):
        '''Template to generate a rotater with operation @op
        A temporary basic block is generated to handle 0-rotate
        @op: operation to execute
        @left (optional): indicates a left rotate if set, default is False
        '''
        # Compute results
        shifter = get_shift(dst, src)
        res = m2_expr.ExprOp(op, dst, shifter)

        # CF is computed with 1-less round than `res`
        new_cf = m2_expr.ExprOp(
            op, dst, shifter - m2_expr.ExprInt(1, size=shifter.size))
        new_cf = new_cf.msb() if left else new_cf[:1]

        # OF is defined only for @b == 1
        new_of = m2_expr.ExprCond(src - m2_expr.ExprInt(1, size=src.size),
                                  m2_expr.ExprInt(0, size=of.size),
                                  res.msb() ^ new_cf if left else (dst ^ res).msb())

        # Build basic blocks
        e_do = [m2_expr.ExprAff(cf, new_cf),
                m2_expr.ExprAff(of, new_of),
                m2_expr.ExprAff(dst, res)
                ]
        # Don't generate conditional shifter on constant
        return (e_do, [])

        # if isinstance(shifter, m2_expr.ExprInt):
        #     if int(shifter) != 0:
        #         return (e_do, [])
        #     else:
        #         return ([], [])
        # e = []
        # lbl_do = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
        # e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
        # e.append(m2_expr.ExprAff(
        #     ir.IRDst, m2_expr.ExprCond(shifter, lbl_do, lbl_skip)))
        # return (e, [IRBlock(lbl_do.name, [AssignBlock(e_do, instr)])])

    miasm2.arch.x86.sem._rotate_tpl = patch_rotate_tpl

    def patch_rotate_with_carry_tpl(ir, instr, op, dst, src):
        # Compute results
        shifter = get_shift(dst, src).zeroExtend(dst.size + 1)
        result = m2_expr.ExprOp(op, m2_expr.ExprCompose(dst, cf), shifter)

        new_cf = result[dst.size:dst.size +1]
        new_dst = result[:dst.size]

        result_trunc = result[:dst.size]
        if op == '<<<':
            of_value = result_trunc.msb() ^ new_cf
        else:
            of_value = (dst ^ result_trunc).msb()
        # OF is defined only for @b == 1
        new_of = m2_expr.ExprCond(src - m2_expr.ExprInt(1, size=src.size),
                                  m2_expr.ExprInt(0, size=of.size),
                                  of_value)


        # Build basic blocks
        e_do = [m2_expr.ExprAff(cf, new_cf),
                m2_expr.ExprAff(of, new_of),
                m2_expr.ExprAff(dst, new_dst)
                ]

        return (e_do, [])
        # Don't generate conditional shifter on constant
        # if isinstance(shifter, m2_expr.ExprInt):
        #     if int(shifter) != 0:
        #         return (e_do, [])
        #     else:
        #         return ([], [])
        # e = []
        # lbl_do = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_skip = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)
        # e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
        # e.append(m2_expr.ExprAff(
        #     ir.IRDst, m2_expr.ExprCond(shifter, lbl_do, lbl_skip)))
        # return (e, [IRBlock(lbl_do.name, [AssignBlock(e_do, instr)])])

    miasm2.arch.x86.sem.rotate_with_carry_tpl = patch_rotate_with_carry_tpl


    def patch_bsr_bsf(ir, instr, dst, src, op_name):
        """
        IF SRC == 0
            ZF = 1
            DEST is left unchanged
        ELSE
            ZF = 0
            DEST = @op_name(SRC)
        """
        # lbl_src_null = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_src_not_null = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

        # aff_dst = m2_expr.ExprAff(ir.IRDst, lbl_next)
        # e = [m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(src,
        #                                                 lbl_src_not_null,
        #                                                 lbl_src_null))]
        # e_src_null = []
        # e_src_null.append(m2_expr.ExprAff(zf, m2_expr.ExprInt(1, zf.size)))
        # # XXX destination is undefined
        # e_src_null.append(aff_dst)

        # e_src_not_null = []
        # e_src_not_null.append(m2_expr.ExprAff(zf, m2_expr.ExprInt(0, zf.size)))
        # e_src_not_null.append(m2_expr.ExprAff(dst, m2_expr.ExprOp(op_name, src)))
        # e_src_not_null.append(aff_dst)

        return [], []
        # return e, [IRBlock(lbl_src_null.name, [AssignBlock(e_src_null, instr)]),
                   # IRBlock(lbl_src_not_null.name, [AssignBlock(e_src_not_null, instr)])]

    # miasm2.arch.x86.sem.bsr_bsf = patch_bsr_bsf

    def patch_div(ir, instr, src1):

        # print '[*] Calling patched div.'

        e = []
        size = src1.size
        if size == 8:
            src2 = mRAX[instr.mode][:16]
        elif size in [16, 32, 64]:
            s1, s2 = mRDX[size], mRAX[size]
            src2 = m2_expr.ExprCompose(s2, s1)
        else:
            raise ValueError('div arg not impl', src1)

        c_d = m2_expr.ExprOp('udiv', src2, src1.zeroExtend(src2.size))
        c_r = m2_expr.ExprOp('umod', src2, src1.zeroExtend(src2.size))

        # if 8 bit div, only ax is affected
        if size == 8:
            e.append(m2_expr.ExprAff(src2, m2_expr.ExprCompose(c_d[:8], c_r[:8])))
        else:
            e.append(m2_expr.ExprAff(s1, c_r[:size]))
            e.append(m2_expr.ExprAff(s2, c_d[:size]))

        return e, []

        # lbl_div = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_except = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

        # do_div = []
        # do_div += e
        # do_div.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
        # blk_div = IRBlock(lbl_div.name, [AssignBlock(do_div, instr)])

        # do_except = []
        # do_except.append(m2_expr.ExprAff(exception_flags, m2_expr.ExprInt(
        #     EXCEPT_DIV_BY_ZERO, exception_flags.size)))
        # do_except.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
        # blk_except = IRBlock(lbl_except.name, [AssignBlock(do_except, instr)])

        # e = []
        # e.append(m2_expr.ExprAff(ir.IRDst,
        #                          m2_expr.ExprCond(src1, lbl_div, lbl_except)))

        # return e, [blk_div, blk_except]

    miasm2.arch.x86.sem.div = patch_div
    miasm2.arch.x86.sem.mnemo_func['div'] = patch_div


    def patch_idiv(ir, instr, src1):
        e = []
        size = src1.size

        if size == 8:
            src2 = mRAX[instr.mode][:16]
        elif size in [16, 32, 64]:
            s1, s2 = mRDX[size], mRAX[size]
            src2 = m2_expr.ExprCompose(s2, s1)
        else:
            raise ValueError('div arg not impl', src1)

        c_d = m2_expr.ExprOp('idiv', src2, src1.signExtend(src2.size))
        c_r = m2_expr.ExprOp('imod', src2, src1.signExtend(src2.size))

        # if 8 bit div, only ax is affected
        if size == 8:
            e.append(m2_expr.ExprAff(src2, m2_expr.ExprCompose(c_d[:8], c_r[:8])))
        else:
            e.append(m2_expr.ExprAff(s1, c_r[:size]))
            e.append(m2_expr.ExprAff(s2, c_d[:size]))

        return e, []

        # lbl_div = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_except = m2_expr.ExprId(ir.gen_label(), ir.IRDst.size)
        # lbl_next = m2_expr.ExprId(ir.get_next_label(instr), ir.IRDst.size)

        # do_div = []
        # do_div += e
        # do_div.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
        # blk_div = IRBlock(lbl_div.name, [AssignBlock(do_div, instr)])

        # do_except = []
        # do_except.append(m2_expr.ExprAff(exception_flags, m2_expr.ExprInt(
        #     EXCEPT_DIV_BY_ZERO, exception_flags.size)))
        # do_except.append(m2_expr.ExprAff(ir.IRDst, lbl_next))
        # blk_except = IRBlock(lbl_except.name, [AssignBlock(do_except, instr)])

        # e = []
        # e.append(m2_expr.ExprAff(ir.IRDst,
        #                          m2_expr.ExprCond(src1, lbl_div, lbl_except)))

        # return e, [blk_div, blk_except]

    miasm2.arch.x86.sem.idiv = patch_idiv    
    miasm2.arch.x86.sem.mnemo_func['idiv'] = patch_idiv

    # print '[*] Miasm patched.'

patch_shift_rotate()


#####################################


class TranslatorC2(Translator):

    __LANG__ = "C2"

    def from_ExprId(self, expr):
        if isinstance(expr.name, asmblock.AsmLabel):
            return "0x%x" % expr.name.offset
        return str(expr)

    def from_ExprInt(self, expr):
        return "%#x" % expr.arg.arg

    def from_ExprAff(self, expr):
        return "%s = %s" % tuple(map(self.from_expr, (expr.dst, expr.src)))

    def from_ExprCond(self, expr):
        return "(%s)?(%s):(%s)" % tuple(map(self.from_expr,
                                        (expr.cond, expr.src1, expr.src2)))

    def from_ExprMem(self, expr):
        if expr.size not in [8, 16, 32, 64]:
            raise NotImplementedError('Unsupported mem size: %d' % expr.size)

        return "*(uint%d_t *)(%s)" % (expr.size, self.from_expr(expr.arg))

    def from_ExprOp(self, expr):

        if len(expr.args) == 1:
            if expr.op in ['!', '-']:
                # return "(~ %s)&0x%x" % (self.from_expr(expr.args[0]),
                                        # size2mask(expr.args[0].size))
                return "%s(%s)" % (expr.op,  self.from_expr(expr.args[0]))
            elif expr.op == 'parity':
                # ignored
                return '0'

            else:
                raise NotImplementedError('Unknown op: %r' % expr.op)

        elif len(expr.args) == 2:
            if expr.op in ['==', '+', '-', '*', '/', '^', '&', '|', '>>', '<<' ]:
                # return '(((%s&0x%x) %s (%s&0x%x))&0x%x)' % (
                #     self.from_expr(expr.args[0]), size2mask(expr.args[0].size),
                #     str(expr.op),
                #     self.from_expr(expr.args[1]), size2mask(expr.args[1].size),
                #     size2mask(expr.args[0].size))
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),str(expr.op),self.from_expr(expr.args[1]))

            elif expr.op == '<<<': # TODO: <<< is << ?
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'<<',self.from_expr(expr.args[1]))

            elif expr.op == '>>>': 
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'>>',self.from_expr(expr.args[1]))

            elif expr.op == 'a>>':
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'>>',self.from_expr(expr.args[1]))

            elif expr.op == 'umod' or expr.op == 'imod':
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'%',self.from_expr(expr.args[1]))

            elif expr.op == 'udiv' or expr.op == 'idiv':
                return  "(%s) %s (%s)" %(self.from_expr(expr.args[0]),'/',self.from_expr(expr.args[1]))

            elif expr.op == "segm":
                # ignore seg register
                return str(self.from_expr(expr.args[1]))

            else:
                raise NotImplementedError('Unknown op: %r' % expr.op)

        elif len(expr.args) >= 3 and expr.is_associative():  # ?????
            oper = ['(%s)' % (self.from_expr(arg))
                    for arg in expr.args]
            oper = str(expr.op).join(oper)
            return oper

        else:
            raise NotImplementedError('Unknown op: %s' % expr.op)

    def from_ExprSlice(self, expr):
        # XXX check mask for 64 bit & 32 bit compat
        return "((%s>>%d) & 0x%X)" % (self.from_expr(expr.arg),
                                      expr.start,
                                      (1 << (expr.stop - expr.start)) - 1)

    def from_ExprCompose(self, expr):
        if expr.size not in [8, 16, 32, 64]:
            raise NotImplementedError('Unsupported size: %d' % expr.size)

        out = []
        # XXX check mask for 64 bit & 32 bit compat
        dst_cast = "uint%d_t" % expr.size
        for index, arg in expr.iter_args():
            out.append("(((%s)(%s & 0x%X)) << %d)" % (dst_cast,
                                                      self.from_expr(arg),
                                                      (1 << arg.size) - 1,
                                                      index))
        out = ' | '.join(out)
        return '(' + out + ')'

def filter_common(expr_value):
    out = []
    for expr, value in sorted(expr_value):
        if (expr, value) in symbols_init.items():
            continue
        if (expr, value) in addition_infos.items():
            continue
        if expr in [regs.zf, regs.cf, regs.nf, regs.of, regs.pf, regs.af,
                    ExprId('IRDst', 32), regs.EIP]:
            continue

        expr = expr_simp(expr.replace_expr(addition_infos))
        value = expr_simp(value.replace_expr(addition_infos))
        
        if expr == value:
            continue

        out.append((expr, value))

    return out

def filter_vmp(expr_value):
    """
        Only care EBP, ESI, memory(base by EBP, EDI).
    """
    out = []
    for expr, value in expr_value:

        if expr in [regs.EBP, regs.ESI]:
            out.append((expr, value))

        elif isinstance(expr, ExprMem):            
            if regs.ESP in expr or regs.ESP_init in expr: 
                continue  # skip ss:[esp] junk
            out.append((expr, value))

        else:
            #out.append((expr, value))
            pass

    return out

def filter_cv(expr_value):

    return expr_value


def state_to_expr(sb, vm='vmp', trans = False):

    sb.del_mem_above_stack(regs.ESP)

    out = filter_common(sb.symbols.items())

    if vm == 'vmp':
        sb.del_mem_above_stack(regs.EBP)
        out = filter_vmp(out)
    elif vm == 'cv':
        out = filter_cv(out)
    else:
        raise NotImplementedError('Unknown VM: %s' % vm)

    buf = ''
    for expr, value in out:

        c2 = TranslatorC2()
        if trans:
            expr_c = c2.from_expr(expr)
            value_c = c2.from_expr(value)
        else:
            expr_c = expr
            value_c = value

        buf +=  '\t%s = %s;\n' % (expr_c, value_c)

    return buf


addition_infos = {}
symbols_init = regs.regs_init.copy()
for expr in symbols_init:
    if expr.size == 1:  # set all flags 0
        symbols_init[expr] = ExprInt(0, 1)


def symexec(handler):
    inst_bytes = handler.bytes_without_jmp
    machine = Machine("x86_32")
    cont = Container.from_string(inst_bytes)
    bs = cont.bin_stream
    mdis = machine.dis_engine(bs, symbol_pool=cont.symbol_pool)

    end_offset = len(inst_bytes)

    mdis.dont_dis = [end_offset]

    asm_block = mdis.dis_block(0)
    # print asm_block
    ira = machine.ira(mdis.symbol_pool)
    ira.add_block(asm_block)

    symb = SymbolicExecutionEngine(ira, symbols_init)

    cur_addr = symb.emul_ir_block(0)
    count = 0
    while cur_addr != ExprInt(end_offset, 32): # execute to end
        cur_addr = symb.emul_ir_block(cur_addr)

        count += 1
        if count > 1000: 
            print '[!] to many loop at %s' % handler.name
            break    

    return symb


if __name__ == '__main__':
    # main()

    vAdd = '8b45000145049c8f4500e9ea140000'.decode('hex')
    vNor = '8b45008b5504f7d0f7d221d08945049c8f4500e97b140000'.decode('hex')
    vShl = '8b45008a4d0483ed02d3e08945049c8f4500e929ffffff'.decode('hex')

    symb = symexec(vAdd)
    print state_to_c(symb)

    # c2 = TranslatorC2()
    # for expr in symb.modified_mems():
    #     print expr
    #     print c2.from_expr(expr_simp(expr))
    # symexec(vNor)
    # symexec(vShl)