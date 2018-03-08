

class RuntimeBlock(object):

    def __init__(self, instructions=None):
        if instructions:
            self._instructions = instructions
        else:
            self._instructions = []

        self.next_addr = set()
        self.prev_addr = set()

# Properties.
    @property
    def start_addr(self):
        return self.instructions[0].addr

    @property
    def addr(self):
        return self.start_addr

    @property
    def end_addr(self):
        return self.instructions[-1].addr

    @property
    def bytes(self):
        return ''.join(ins.bytes for ins in self.instructions)

    @property
    def diasm(self):
        return '\n'.join(ins.diasm for ins in self.instructions)

    def __str__(self):
        return '\n'.join(str(ins) for ins in self.instructions)


# Util method.
    def has_addr(self, addr):
        return addr in (ins.addr for ins in self.instructions)

    def add_instruction(self, ins):
        self.instructions.append(ins)

    def add_next(self, addr):
        self.next_addr.add(addr)

    def add_prev(self, addr):
        self.prev_addr.add(addr)


    def split_at(self, addr):
        """
        Split this RuntimeBlock at address(addr). Truncate this block and return another new block.
        If addr not in this block or is block head, return None.
        """
        if not self.has_addr(addr) or addr == self.addr:
            return None
            
        addrs = [ins.addr for ins in self._instructions]
        addr_idx = addrs.index(addr)
        new_instructions = self._instructions[addr_idx:]
        self.instructions = self._instructions[0:addr_idx]

        new_block = RuntimeBlock(new_instructions)


        new_block.add_prev(self.addr)
        self.add_next(addr)

        return new_block

    

