# coding:utf-8

import struct
import cPickle
import time
import os
import sys

from functools import wraps

# my code
import symexec 

# so @profile won't throw error when running without line_profiler.
if 'profile' not in  dir(__builtins__):
    profile = lambda func: func

def time_profile(orig_func):
    @wraps(orig_func) # wraps make wrap_func.__name__ = func
    def wrap_func(*args, **kwargs):
        time_start = time.time()
        result = orig_func(*args, **kwargs)
        time_end = time.time()
        print 'Running %s(): %0.4f seconds' % (orig_func.func_name, time_end - time_start)
        return result
    return wrap_func


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
        if not self.consolidated:
            return sum(i.size for i in self._instructions)
        else:
            return self.size + sum(i.size for i in self.sub_blocks)

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
        return [ i.addr for i in self.instructions ]

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
        return '<Block(%#x - %#x) INS(%d) PREV(%d) NEXT(%d) EXEC(%d) LOOP(%d)\n>' % (
            self.start_addr, self.end_addr, self.ins_count,
            self.prev_count,  self.next_count, self.exec_count, self.loop_count)


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

class BBLManager(object):

    def __init__(self):
        self.blocks = {}  # (addr, block)
        self.loops = set()
        self.head_block = None  # first block in parse phrase
        self.head_addr  = None  # first address in execute phrase

        #=======
        self.handlers = {}    # { dispatcher_addr : [handler_addr, ...]}  

    def _add_loop(self, loop):
        # return True if a new loop is appended.        
        if loop in self.loops:
            return False
        else:
            self.loops.add(loop) # this will call loop.__hash__()
            return True

    @time_profile
    def load_ins_info(self, filename):
        """
        load instructions address, disassembly and binary bytes. 
        """
        print '[+] Loading instructions info from %s' % filename

        import instruction

        for ins in instruction.parse_file(filename):
            b = BasicBlock()
            b.add_ins(ins)
            self.blocks[b.addr] = b
            


        # blocks = open(filename, 'rb').read().split('####BBL\n')[1:] # skip first ''
        # for buf in blocks:
        #     lines = buf.splitlines()
        #     try:
        #         start_addr, end_addr, size, ins_count = lines[0].split('\t')
        #     except ValueError,e:
        #         print e, 'at line:', lines
        #         continue

        #     start_addr = int(start_addr,16)
        #     end_addr = int(end_addr, 16)
        #     size = int(size,10)
        #     ins_count =  int(ins_count,10)  # not used.

        #     b = BasicBlock(start_addr, end_addr, size)

            if not self.head_block:
                self.head_block = b

        #     # parse ins
        #     for line in lines[1:]:
        #         addr, dis = line.split('\t')
        #         addr = int(addr,16)
        #         b.ins.append((addr, dis))


        #     if start_addr not in self.blocks:   
        #         self.blocks[start_addr] = b
        #     else:
        #         # TODO: handle block at same address.
        #         # of course this will never happen when we use INS trace.
        #         if self.blocks[start_addr].size != b.size:
        #             print '='*40 + 'Block collision!'
        #             print self.blocks[start_addr]
        #             print '='*40
        #             print b
        #             print '='*40

    # ==============================================================================


    @profile
    def _buffer_process_addr(self, filename,start_addr = None, end_addr = None, x64=False):
        """
        buffered io. faster. 
        """
        # get file size.
        f = open(filename, 'rb')
        f.seek(0,2) # to end
        filesize = f.tell()
        f.seek(0)

        # compatible x86 & x64.
        BUFSIZE = 1024*1024*10*2
        if x64:
            ADDR_SIZE = 8
            ADDR_FMT = 'Q'
        else:  # x86
            ADDR_SIZE = 4
            ADDR_FMT = 'I'

        read_size = 0
        started = False
        ended = False

        # read block addr sequence.
        while True:
            addrs = f.read(BUFSIZE) # read larger buffer goes faster.
            read_size += len(addrs)
            if len(addrs) == 0: break
            assert len(addrs) % ADDR_SIZE == 0

            addrs = struct.unpack(ADDR_FMT*(len(addrs)/ADDR_SIZE), addrs)

            # start at start_addr.
            if start_addr and not started:
                if start_addr not in addrs:
                    continue
                else:
                    addrs = addrs[ addrs.index(start_addr): ]
                    started = True

            # end at end_addr
            if end_addr:
                if end_addr in addrs:
                    addrs = addrs[ : addrs.index(end_addr)]
                    ended = True

            # this works faster than "for addr in addrs: yield addr"
            yield addrs

            if read_size % (BUFSIZE) == 0:
                print '\r%0.2f %% processed\t%s' % (read_size*100.0/filesize, time.asctime())

            if ended:
                break

        f.close()





    @time_profile
    @profile
    def load_trace(self, filename, start_addr = None, end_addr = None, x64=False):
        """
        Construct BBL graph. head_block is set here.

        filename: trace file.
        start_addr: start processing at this address. (start_addr will be processed)
        end_addr: stop processing at this address. (end_addr will *not* be processed)
        x64: True for x64 , False for x86
        """

        print '[+] Loading trace from %s' % filename

        prev_block = None

        addr_seq = []
        addr_set = set()

        loops   = []


        for addrs in self._buffer_process_addr(filename, start_addr, end_addr, x64):
            for addr in addrs:

                # Construct graph.
                if not self.head_addr:
                    self.head_addr = addr

                cur_block = self.blocks[addr]
                cur_block.exec_count += 1
                if prev_block:              
                    cur_block.add_prev(prev_block.start_addr)
                    prev_block.add_next(cur_block.start_addr)
                prev_block = cur_block

                # Finding loops.
                if addr in addr_set: # set(using hash to search) is much faaaaaster than list.
                    # loop found.
                    loop_start = addr_seq.index(addr)
                    loop = BlockLoop(addr_seq[loop_start: ])
                    
                    #loop = tuple(addr_seq[loop_start: ])
                    addr_seq =  addr_seq[ :loop_start]
                    for i in loop.addr_seq:     
                        addr_set.remove(i)          

                    if(self._add_loop(loop)):
                        #for node in loop.list_nodes(self):
                        #    node.add_loop(loop)
                        self.blocks[addr].add_loop(loop) # head node.

                addr_seq.append(addr)
                addr_set.add(addr)

        # clear dead block whose exec_count is 0.
        for addr in self.blocks.keys():
            if self.blocks[addr].exec_count == 0:
                self.blocks.pop(addr)

    # ==============================================================================
    # Use DFS algrithm to search graph to find circles staticly, but we got a lot more senseless results.

    def _dfs_find_circle(self, addr, path = []):
                
        if addr in path:
            # circle found.
            # yield path[path.index(addr):]
            circle = path[path.index(addr):]
            self.loops.append(circle)
            for addr in circle:
                self.blocks[addr].add_loop(circle)
            return 

        else:
            path.append(addr)
            for next_addr in self.blocks[addr].nexts:
                # only for py3
                # yield from self._dfs_find_circle(self, next_addr, path)
                self._dfs_find_circle(next_addr, path)
            path.pop()
            return

    # result make no sense !!!! 
    # use loops generated from trace.

    def find_all_circle(self):
        self.loops = []
        self._dfs_find_circle(self.head_addr)

    # ==============================================================================

    def _hot_blocks(self, loop_count_min):
        return filter(self.blocks.values(), lambda node: node.loop_count > loop_count_min )


    # ==============================================================================

    def _can_merge_to_prev(self, cur):
        if cur.prev_count != 1 : return False
        prev = self.blocks[cur.prevs.keys()[0]]
        if prev.next_count != 1: return False
        return True


    def _merge_to_prev(self, cur):
        prev = self.blocks[cur.prevs.keys()[0]]

        # this shoud be same
        assert prev.exec_count == cur.exec_count
        prev.merge_block(cur)
        self.blocks.pop(cur.start_addr)

        # # start not change
        # prev.end_addr = cur.end_addr

        # prev.size += cur.size
        # prev.ins_count += cur.ins_count
        # prev.ins += cur.ins

        # # prev.prevs not change
        # prev.nexts = cur.nexts

        # fix cur->next->prev.
        for addr in prev.nexts:
            next_block = self.blocks[addr]
            next_block.prevs.pop(cur.addr) # remove reference to current block
            next_block.prevs[prev.addr] = cur.prevs[prev.addr] # add reference to prev block



    def _repair_loop(self):
        for loop in self.loops:
            i = 0
            block = None
            new_addr_seq = []
            last_idx = 0

            for i, addr in enumerate(loop.addr_seq):
                if addr in self.blocks:
                    new_addr_seq.append(addr)
                    if block:
                        assert tuple(block.ins_addrs) == loop.addr_seq[last_idx:i]
                        last_idx = i                    
                    block = self.blocks[addr]
            assert tuple(block.ins_addrs) == loop.addr_seq[last_idx:i+1]

            loop.addr_seq = tuple(new_addr_seq)


    @time_profile
    def consolidate_blocks(self):
        """
        if current node has unique predecessor and the predecessor has unique successor, 
        consolidate current node with the predecessor. 
        """
        print 'before consolidation: %d'%len(self.blocks)

        for addr in self.blocks.keys():
            node =  self.blocks[addr]
            if self._can_merge_to_prev(node):
                self._merge_to_prev(node)

        print 'after consolidation: %d'% len(set(self.blocks.values()))

        # Consolidate blocks of loops
        self._repair_loop()


    # ==============================================================================


    def display_bbl_graph(self):
        """
        draw basic block graph with pydot.
        """
        import pydot
        g = pydot.Dot(g_type='dig') # directed graph
        for node in self.blocks.values():
            if node.exec_count == 0: continue

            g.add_node(pydot.Node(node.start_addr, 
                label= '%#x(%d) %d'%(node.start_addr, node.ins_count, node.exec_count) 
                #label = node.ins_str().replace('\n','\l')  # make text left-aligned.
                #label = str(node).replace('\n','\l')
                ))
            for next_addr in node.nexts:
                g.add_edge(pydot.Edge(node.start_addr, next_addr, label = str(node.nexts[next_addr])))

        
        import os
        g.write_jpg("test.jpg")
        os.system('test.jpg')
        #g.write_svg("test.svg")
        #os.system('"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" test.svg')


    def display_bbl_graph_ida(self):
        """
        draw basic block graph with IDA pro. much faster!!!
        """
        try:
            from idaapi import GraphViewer
        except:
            print 'Must run in IDA pro !!'
            return 

        class MyGraph(GraphViewer):
            def __init__(self, bm):
                GraphViewer.__init__(self, 'BBL graph')
                self.bm=bm

            def OnRefresh(self):
                print 'OnRefresh'
                self.Clear()
                self._nodes = bm.blocks.values()

                for node in self._nodes:
                    for next_addr in node.nexts:
                        g.AddEdge(self._nodes.index(node), self._nodes.index(bm.blocks[next_addr])) 

                return True

            def OnGetText(self, node_id):
                node = self[node_id]
                #if self.Count() < 100:
                #   return '%#x(%d) %d\n%s'%(node.start_addr, node.ins_count, node.exec_count, node.ins_str())
                #else:
                #   return '%#x(%d) %d'%(node.start_addr, node.ins_count, node.exec_count)
                return str(self[node_id])

        g = MyGraph(self)
        g.Show()

    # ==============================================================================


    def sorted_blocks(self, sorted_by):
        cmp_map = { 
        "prev_count": lambda x,y : x.prev_count - y.prev_count,
        "next_count": lambda x,y : x.next_count - y.next_count,
        "ins_count": lambda x,y : x.ins_count - y.ins_count,
        "exec_count": lambda x,y : x.exec_count - y.exec_count,
        "prev_mul_next_count": lambda x,y : x.prev_count*x.next_count - y.prev_count*y.next_count,
        "loop_count":  lambda x,y : x.loop_count - y.loop_count,
        }

        if sorted_by not in cmp_map:
            print "sorted by: " + ','.join(cmp_map)
            return

        # descending sort.
        return sorted(self.blocks.values(), cmp_map[sorted_by], reverse=True)

    # Searching address which is not start address of block can be slow. 
    def addr_to_block(self, addr):
        if addr in self.blocks:
            return self.blocks[addr]
        else:
            for block in self.blocks.values():
                if addr in block.ins_addrs:
                    return block


    # ==============================================================================



    def draw_block_loop_ida(self, block, loop_length=5):
        """
        draw basic block graph with IDA pro. much faster!!!
        """
        try:
            from idaapi import GraphViewer
        except:
            print 'Must run in IDA pro !!'
            return 

        class MyGraph(GraphViewer):
            def __init__(self, bm):
                GraphViewer.__init__(self, 'BBL graph')
                self.bm=bm

            def OnRefresh(self):
                print 'OnRefresh'
                self.Clear()
                block_set = [] 

                # set.union(*[set(lp.addr_seq[:loop_length]) for lp in block.loops])
                # this graph looks better.
                for lp in block.loops:
                    for addr in lp.addr_seq[:loop_length]:
                        if addr not in block_set:
                            block_set.append(addr)



                self._nodes = [bm.blocks[addr] for addr in block_set]

                for node in self._nodes:
                    for next_addr in node.nexts:
                        if next_addr in block_set:
                            g.AddEdge(self._nodes.index(node), self._nodes.index(bm.blocks[next_addr])) 

                return True

            def OnGetText(self, node_id):
                node = self[node_id]
                #if self.Count() < 100:
                #   return '%#x(%d) %d\n%s'%(node.start_addr, node.ins_count, node.exec_count, node.ins_str())
                #else:
                #   return '%#x(%d) %d'%(node.start_addr, node.ins_count, node.exec_count)
                return str(self[node_id])

        g = MyGraph(self)
        g.Show()


    def detect_dispatchers(self):

        # detect vmp 2.x loop, ugly code, but works.
        dispatchers = filter(lambda b: b.loop_count > 5 and b.next_count*2 > b.loop_count,
            self.sorted_blocks('loop_count'))

        print '[+] %d dispatcher(s) found.' % len(dispatchers) 
        for block in dispatchers:
            self.handlers[block.addr] = block.nexts
        return dispatchers

    def dump_handlers(self):

        for dispatcher_addr in self.handlers:
            block = self.blocks[dispatcher_addr]
            print 'Dispatcher:'
            print block.ins_str

            handler_addrs = self.handlers[dispatcher_addr]
            print '[+] %d Handler(s):' % len(handler_addrs)
            for addr in handler_addrs:                
                handler = self.blocks[addr]
                print '#'*80
                print 'Handler:'
                # print bm.blocks[addr].bytes.encode('hex')
                print handler.ins_str 
                print 'C repr:'
                print handler.to_c()      

        print '='*20



def dump_bm(infofile, tracefile, dumpfile, x64=False):
    global bm
    bm = BBLManager()
    bm.load_ins_info(infofile)
    bm.load_trace(tracefile,x64=x64)    
    bm.consolidate_blocks()
    cPickle.dump(bm, open(dumpfile,'wb'))   


def load_bm(dumpfile):
    global bm
    bm = cPickle.load(open(dumpfile,'rb'))
    


def run_pin_and_dump(exe_path):

    cmd = r'..\..\..\pin.exe  -t obj-ia32\MyPinTool.dll -logins -- %s' % exe_path
    os.system(cmd)

    infofile = r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\INS.info'
    tracefile = r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\INS.trace'

    abspath = os.path.abspath(exe_path)
    exe_name = os.path.splitext(os.path.basename(abspath))[0]
    dumpfile = r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\%s.dump' % exe_name
    dump_bm(infofile, tracefile ,dumpfile)

    print bm.sorted_blocks('loop_count')[:10]    

def load_from_exepath(exe_path):
    abspath = os.path.abspath(exe_path)
    exe_name = os.path.splitext(os.path.basename(abspath))[0]
    dumpfile = r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\%s.dump' % exe_name
    load_bm(dumpfile)

def main(path):
    run_pin_and_dump(path)
    #load_from_exepath(path)


if __name__ == '__main__':
    # main(sys.argv[1])
    # load_bm(r'D:\paper\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\base64.vmp_1.81_demo.dump')
    # for dispatcher in bm.detect_vm_loop():
    #     bm.draw_block_loop_ida(dispatcher)
    global bm
    bm = BBLManager()
    bm.load_ins_info('../bin.ins')
    bm.load_trace('../bin.trace') 
    # bm.load_trace('../bin.block')      
    bm.consolidate_blocks()
    # cPickle.dump(bm, open('test.dump','wb')) 
    # bm.display_bbl_graph()

    bm.detect_dispatchers() 
    bm.dump_handlers()


    