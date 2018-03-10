
import config

class Handler(object):

    DEFAULT_NAME = 'Handler'

    def __init__(self):
        self.blocks = []
        self.head = None
        self.tail = None

        self.copy = [] # same handler

        self._name = None

    @property
    def name(self):
        if self._name:
            return self._name
        else:
            return 'Handler_%x' % self.addr

    def __repr__(self):
        return '<%s>' % self.name

    def add_block(self, block):
        if not self.head:
            self.head = block

        if self.tail:
            if block.addr not in self.tail.nexts:
                return False

        # every block.exec_count must <= head.exec_count 
        if block.exec_count > self.head.exec_count:
            return False

        self.blocks.append(block)
        self.tail = block

        return True

    def add_copy(self, handler):
        self.copy.append(handler)


    @property
    def is_valid(self):
        return self.head is not None

    @property
    def addr(self):
        return self.head.addr


    @property
    def bytes(self):
        return ''.join(b.bytes for b in self.blocks)

    @property
    def instructions(self):
        ins = []
        for b in self.blocks:
            ins += b.instructions
        return ins

    @property
    def ins_str(self):
        return '\n'.join(b.ins_str for b in self.blocks)    


    def __str__(self):
        buf = self.name
        buf += '(%#x) %d blocks' % (self.addr, len(self.blocks))
        for b in self.blocks:
            buf += '\n\t' + repr(b)
        
        if len(self.copy) > 0:
            buf += '\n[COPY] '+ '\n'.join(str(i) for i in self.copy)

        return buf
    

    @property    
    def bytes_without_jmp(self):
        """
        Clear all jump instructions.

        jmp -> nop
        jxx -> nop
        call xxx -> push ret_addr
        """

        buf = ''

        from miasm2.arch.x86.arch import mn_x86
        from miasm2.arch.x86.arch import conditional_branch
        from miasm2.arch.x86.arch import unconditional_branch
        from miasm2.expression.expression import ExprInt

        branch_name =  conditional_branch + unconditional_branch
        call_name = ['CALL']

        for ins in self.instructions:
            ins_x86 =  mn_x86.dis(ins.bytes, 32)

            if ins_x86.name in branch_name:
                buf += '\x90'  #  NOP
            elif ins_x86.name in call_name:
                ret_addr = ExprInt(ins.addr + ins.size, 32)
                ins_x86.args = [ret_addr]
                ins_x86.name = 'PUSH'
                buf += mn_x86.asm(ins_x86)[0]
            else:
                buf += ins.bytes

        return buf


    @property
    def ins_str_with_trace(self):
        buf = ''
        for ins in self.instructions: 
            trace = ins.traces[0]
            buf += str(ins) + '\t; ' + trace.change_str
            buf += '\n'

        return buf

    @property
    def ins_str_without_jmp(self):
        from miasm2.arch.x86.disasm import dis_x86_32
        buf = self.bytes_without_jmp
        d = dis_x86_32(buf)
        d.dont_dis = [len(buf)]
        return str(d.dis_block(0))


    def to_sym_state(self):
        import symexec
        sb = symexec.symexec(self)
        return sb


    def to_expr(self):
        sb = self.to_sym_state()
        import symexec
        return symexec.state_to_expr(sb, config.VM, False)

    def to_c(self):
        sb = self.to_sym_state()
        import symexec
        c_str = symexec.state_to_expr(sb, config.VM, True)
        return c_str


