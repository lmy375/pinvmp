
import config

from symexec import SymExecObject

class Handler(SymExecObject):

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
    



