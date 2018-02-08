

class Instruction(object):

    def __init__(self, addr, disasm, bytes):
        self.addr = addr
        self.disasm = disasm
        self.bytes = bytes
        self.trace = None

    def __str__(self):
        # return '%#x\t%s\t%s' % (self.addr, 
        #     self.bytes.encode('hex').upper(),
        #     self.disasm)
        return '%#x\t%s' % (self.addr, self.disasm)

    @property
    def size(self):
        return len(self.bytes)
        

def parse_file(filepath):
    for line in open(filepath, 'rb').read().splitlines():
        addr , diasm, hexbytes = line.split('\t')
        yield Instruction(int(addr, 16), diasm, hexbytes.decode('hex'))


if __name__ == '__main__':
    for ins in parse_file('../bin.ins'):
        print ins