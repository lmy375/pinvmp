

class BasicBlock(object):

    def __init__(self, instructions=None):
        # instructions sequence. (instruction.Instruction)
        if instructions:
            self._instructions = instructions
        else:
            self._instructions = []

        self.loops = set()

        self.visited = False # for DFS.

        # times of execution.
        self.exec_count = 0

        # next, prev block address.  (addr, call_count)
        # use address instead of reference, or cPickle.dump throw a recursion error.
        self._nexts = {}
        self._prevs = {}

        # Self.consolidated is True when sub_blocks is not empty
        self.sub_blocks = []


    @property
    def consolidated(self):
        return self.sub_blocks

    @property
    def start_addr(self):
        return self._instructions[0].addr

    @property
    def addr(self):
        return self.start_addr

    @property
    def nexts(self):
        if not self.consolidated:
            return self._nexts
        else:
            return self.sub_blocks[-1].nexts

    @property
    def prevs(self):
        return self._prevs


    @property
    def end_addr(self):
        if not self.consolidated:
            return self._instructions[-1].addr
        else:
            return self.sub_blocks[-1].end_addr

    @property
    def size(self):
        self_size = sum(i.size for i in self._instructions)
        if not self.consolidated:
            return self_size
        else:
            return self_size + sum(i.size for i in self.sub_blocks)

    @property
    def instructions(self):
        if not self.consolidated:
            return self._instructions
        else:
            tmp_ins = list(self._instructions)
            for b in self.sub_blocks:
                tmp_ins += b._instructions
            return tmp_ins

    def add_ins(self, ins):
        self._instructions.append(ins)

    @property
    def ins_addrs(self):
        return [i.addr for i in self.instructions]

    @property
    def ins_count(self):
        return len(self.instructions)

    def add_prev(self, addr):
        #if addr not in self.prevs:
        #   self.prevs[addr] = 1
        #else:
        #   self.prevs[addr] += 1
        try:
            self.prevs[addr] += 1
        except KeyError:
            self.prevs[addr] = 1


    def add_next(self, addr):
        # if addr not in self.nexts:
        #     self.nexts[addr] = 1
        # else:
        #     self.nexts[addr] += 1
        try:
            self.nexts[addr] += 1
        except KeyError:
            self.nexts[addr] = 1

    @property
    def prev_count(self):
        return len(self.prevs)

    @property
    def next_count(self):
        return len(self.nexts)


    def prev_blocks(self, bm):
        return [bm.blocks[addr] for addr in self.prevs]

    def next_blocks(self, bm):
        return [bm.blocks[addr] for addr in self.nexts]

    @property
    def ins_str(self):
        return '\n'.join(str(i) for i in self.instructions) # including sub-blocks.

    @property
    def bytes(self):
        return ''.join(i.bytes for i in self.instructions)

    def add_loop(self, loop):
        self.loops.add(loop)

    @property
    def loop_count(self):
        return len(self.loops)

    def __str__(self):
        buf = ''
        buf += 'Block(%#x - %#x) SIZE(%d) INS(%d) EXEC(%d) LOOP(%d)\n' % (
            self.start_addr, self.end_addr,
            self.size, self.ins_count, self.exec_count, self.loop_count)
        buf += 'Prev (%d):\n' % self.prev_count
        buf += '\t'+','.join(hex(i) for i in self.prevs) + '\n'
        buf += 'Next (%d):\n' % self.next_count
        buf += '\t'+','.join(hex(i) for i in self.nexts) + '\n'
        buf += 'Instructions:\n'
        buf += ''.join('\t%s\n' % str(i) for i in self.instructions)
        return buf

    def __repr__(self):
        return '<Block(%#x - %#x) INS(%d) PREV(%d) NEXT(%d) EXEC(%d) LOOP(%d)>' % (
            self.start_addr, self.end_addr, self.ins_count,
            self.prev_count, self.next_count, self.exec_count, self.loop_count)


    def merge_block(self, block):
        """
        Merge sequential block, used in BBLManager.consolidate_blocks()
        """
        # note that block to merge may be consolidated, too.
        self.sub_blocks.append(block)
        self.sub_blocks += block.sub_blocks
        block.sub_blocks = []

    def to_c(self):
        import symexec
        sb = symexec.symexec(self.bytes)
        c_str = symexec.state_to_c(sb)
        return c_str

class BlockLoop(object):

    def __init__(self, addr_seq):
        self.addr_seq = tuple(addr_seq)

    def __cmp__(self, obj):
        if isinstance(obj, self.__class__):
            return cmp(self.addr_seq, obj.addr_seq)

        if obj is self: return 0

        if type(obj) is list or type(obj) is tuple:
            return cmp(self.addr_seq, obj)

        return cmp(self, obj)

    def __hash__(self):
        return hash(self.addr_seq)

    def list_nodes(self, bm):
        for addr in self.addr_seq:
            yield bm.blocks[addr]

    def __repr__(self):
        buf = "loop: "
        buf += ','.join(hex(i) for i in self.addr_seq[:5])
        if len(self.addr_seq) > 5:
            buf += '.. %d nodes' % len(self.addr_seq)
        return buf

    def __str__(self):
        return '[ %s ]' % ', '.join(hex(i) for i in self.addr_seq)