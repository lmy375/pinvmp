import struct 

class Trace(object):
    """docstring for Trace"""
    def __init__(self, id, addr):
        self.addr = addr
        self.id = id

        # TODO:
        self.mem_read = {} # addr, value
        self.mem_write = {}
        self.reg_read = {} # reg, value
        self.reg_write = {}

    def __str__(self):
        return '%#x' % self.addr

TRACE_FORMAT = 'I'
TRACE_SIZE = 4

def parse_file(filepath):

    f = open(filepath, 'rb')
    id = 0
    while True:
        buf = f.read(TRACE_SIZE)
        yield Trace(id, struct.unpack(TRACE_FORMAT, buf))
        id += 1

if __name__ == '__main__':
    for ins in parse_file('../bin.trace'):
        print ins
