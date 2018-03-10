import struct 

class Trace(object):
    """docstring for Trace"""
    def __init__(self, id, addr):
        self.id = id
        self.addr = addr

        self.mem_read = {} # addr, value
        self.mem_write = {}
        self.reg_read = {} # reg, value
        self.reg_write = {}

    @property
    def change_str(self):
        buf = ''
        for reg in self.reg_read:
            buf += '\t'
            buf += '%s->%#x' % (reg, self.reg_read[reg])

        for reg in self.reg_write:
            buf += '\t'
            buf += '%s<-%#x' % (reg, self.reg_write[reg])

        for addr in self.mem_read:
            buf += '\t'
            buf += '[%#x]->%#x' % (addr, self.mem_read[addr])

        for addr in self.mem_write:
            buf += '\t'
            buf += '[%#x]<-%#x' % (addr, self.mem_write[addr])
        return buf.strip('\t') # skip 1st '\t'

    def __str__(self):
        buf = '[%d]\t%#x\t' % (self.id, self.addr)
        buf += self.change_str
        return buf

    def __repr__(self):
        return '<Trace [%d] %#x >' % (self.id, self.addr)

    def add_reg_read(self, reg_name, value):
        self.reg_read[reg_name] = value

    def add_reg_write(self, reg_name, value):
        self.reg_write[reg_name] = value

    def add_mem_read(self, addr, value):
        self.mem_read[addr] = value

    def add_mem_write(self, addr, value):
        self.mem_write[addr] = value

    def add_change(self, change):
        assert not change.is_start, 'START change can not be added.'
        if change.is_reg:
            if change.is_read:
                self.add_reg_read(change.reg_name, change.value)
            else:
                self.add_reg_write(change.reg_name, change.value)
        else:
            assert change.is_mem
            if change.is_read:
                self.add_mem_read(change.addr, change.value)
            else:
                self.add_mem_write(change.addr, change.value)

IS_WRITE = 0x40000000
IS_MEM = 0x20000000
IS_START = 0x10000000

CHANGE_FORMAT = 'IIQQ'
CHANGE_SIZE = 24

REG_NAME_MAP = {
    0 : 'eax',
    4 : 'ecx',
    8 : 'edx',
    12 : 'ebx',
    16 : 'esp',
    20 : 'ebp',
    24 : 'esi',
    28 : 'edi',
    32 : 'eip'
}

class Change(object):
    def __init__(self, buf):
        id, flags, addr, data = struct.unpack(CHANGE_FORMAT, buf)
        self.id = id
        self.flags = flags
        self.addr = addr
        self.data = data

    @property
    def value(self):
        return self.data

    @property
    def is_mem(self):
        return self.flags & IS_MEM

    @property
    def is_reg(self):
        return not self.is_mem

    @property
    def reg_name(self):
        assert self.is_reg
        return REG_NAME_MAP[self.addr]

    @property
    def is_write(self):
        return self.flags & IS_WRITE

    @property
    def is_read(self):
        return not self.is_write

    
    @property
    def is_start(self):
        return self.flags & IS_START


    def __str__(self):
        if self.is_start:
            return '[START]\t%#x' % self.addr
        elif self.is_reg:
            if self.is_read:
                return '[R]\t%s -> %#x' % (self.reg_name, self.data)
            else:
                return '[W]\t%s <- %#x' % (self.reg_name, self.data)
        elif self.is_mem:
            if self.is_read:
                return '[R]\t[%#x] -> %#x' % (self.addr, self.data)
            else:
                return '[W]\t[%#x] <- %#x' % (self.addr, self.data)
        else:
            return '[INVALID]'

def parse_file(filepath):

    f = open(filepath, 'rb')

    trace = None

    while True:
        buf = f.read(CHANGE_SIZE)

        if len(buf) != CHANGE_SIZE:
            if trace: yield trace
            return

        c = Change(buf)
        #print c

        if c.is_start:
            if trace: yield trace
            trace = Trace(c.id, c.addr)
        else:
            trace.add_change(c)


if __name__ == '__main__':
    count = 0
    global g
    for trace in parse_file('../bin.trace'):
        g = trace
        print trace
        count += 1
        # if count == 100: break