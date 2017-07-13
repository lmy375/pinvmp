


import instructions
import trace
import runtimeblock

class Program(object):
    """docstring for Program"""
    def __init__(self, arg):

        self.instructions = {} # addr, instructions
        self.runtimeblocks = {}



    def load_instructions(self, filepath):
        for ins in instructions.parsefile(filepath):
            self.instructions[ins.addr] = ins

    def load_trace(self, filepath):
        current_block = RuntimeBlock()
        coverred_addr = set()  

        for t in trace.parsefile(filepath):
            if t.addr not in self.instructions:
                raise Exception("Unknown address at %#x" % t.addr)
            inst = self.instructions[addr]
            if t.addr not in coverred_addr:
                current_block.


        