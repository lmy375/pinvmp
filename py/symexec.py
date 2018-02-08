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

def patch_shift():
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

        return e_do, []

    import  miasm2.arch.x86.sem
    miasm2.arch.x86.sem._shift_tpl = patch_shift_tpl

patch_shift()


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




addition_infos = {}
symbols_init = regs.regs_init.copy()
for expr in symbols_init:
    if expr.size == 1:  # set all flags 0
        symbols_init[expr] = ExprInt(0,1)

def state_to_c(sb):
    """
        Dump mem(ebp or global), reg(ebp, esi)
    """

    # print '-'*20, "State", '-'*20
    out = {}
    for expr, value in sorted(sb.symbols.items()):
        if (expr, value) in symbols_init.items():
            continue
        if (expr, value) in addition_infos.items():
            continue
        if expr in [regs.zf, regs.cf, regs.nf, regs.of, regs.pf, regs.af,
                    ExprId('IRDst', 32), regs.EIP]:
            continue
        expr_s = expr_simp(expr.replace_expr(addition_infos))
        expr = expr_s
        value = expr_simp(value.replace_expr(addition_infos))
        if expr == value:
            continue
        out[expr] = value

    out = sorted(out.iteritems())
    x86_regs = []
    mem = []
    other = []
    for expr, value in out:
        c2 = TranslatorC2()
        print 'before: \n%s = %s\n' % (expr, value)
        expr_c = c2.from_expr(expr)
        value_c = c2.from_expr(value)
        # print 'after: \n%s = %s\n' % (expr_c, value_c)

        if expr in [regs.EBP]:
            x86_regs.append((expr_c, value_c))
        elif isinstance(expr, ExprMem):            
            if regs.ESP in expr or regs.ESP_init in expr : continue  # skip ss:[esp] junk
            mem.append((expr_c, value_c))
        else:
            other.append((expr_c, value_c))

    buf = ''
    # print "Mem:"
    for item in mem:
        buf +=  '\t%s = %s;\n' % item
    # print "Reg:"
    for item in x86_regs:
        buf +=  '\t%s = %s;\n' % item
    # print
    return buf


def symexec(inst_bytes):
    machine = Machine("x86_32")
    cont = Container.from_string(inst_bytes)
    bs = cont.bin_stream
    mdis = machine.dis_engine(bs, symbol_pool=cont.symbol_pool)


    asm_block = mdis.dis_bloc(0)
    # print asm_block
    ira = machine.ira(mdis.symbol_pool)
    ira.add_bloc(asm_block)

    symb = SymbolicExecutionEngine(ira, symbols_init)

    cur_addr = symb.emul_ir_block(0)

    symb.del_mem_above_stack(regs.EBP)

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