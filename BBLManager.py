# coding:utf-8

import struct
import cPickle
import time



class BasicBlock(object):

	def __init__(self, start_addr, end_addr, size, ins_count):
		self.start_addr = start_addr
		self.end_addr = end_addr
		self.size = size
		self.ins_count = ins_count

		self.loops = []

		# instructions sequence. (addr, disassemble)
		self.ins = []
		# times of execution.
		self.exec_count = 0

		# next, prev block address.  (addr, call_count)
		# 这里用地址，不用对象引用。用对象引用cPickle dump时会发生递归错误
		self.nexts = {}
		self.prevs = {}

		# before consolidation, all instructions are staticly sequential.
		# after consolidation, block is combination of runtime blocks sequences.
		self.consolidated = False


	def add_prev(self, addr):
		if addr not in self.prevs:
			self.prevs[addr] = 1
		else:
			self.prevs[addr] += 1

	def add_next(self, addr):
		if addr not in self.nexts:
			self.nexts[addr] = 1
		else:
			self.nexts[addr] += 1

	def prev_count(self):
		return len(self.prevs)

	def next_count(self):
		return len(self.nexts)


	def prev_blocks(self, bm):
		return [bm.blocks[addr] for addr in self.prevs]

	def next_blocks(self, bm):
		return [bm.blocks[addr] for addr in self.nexts]


	def ins_str(self):
		return ''.join('%#x\t%s\n' % (addr, dis) for addr, dis in self.ins)

	def add_loop(self, loop):
		if loop not in self.loops:
			self.loops.append(loop)
		# nodes shoud never modify loop count !!!	

	def loop_count(self):
		return len(self.loops)

	def __str__(self):
		buf = ''
		buf += 'Block(%#x - %#x) SIZE(%d) INS(%d) EXEC(%d) LOOP(%d)\n' % (
			self.start_addr, self.end_addr, 
			self.size, self.ins_count, self.exec_count, self.loop_count())
		buf += 'Prev (%d):\n' % self.prev_count()
		buf += '\t'+','.join(hex(i) for i in self.prevs) + '\n'
		buf += 'Next (%d):\n' % self.next_count()
		buf += '\t'+','.join(hex(i) for i in self.nexts) + '\n'
		buf += 'Instructions:\n'
		buf += ''.join('\t%#x\t%s\n' % (addr, dis) for addr, dis in self.ins)
		return buf

	def __repr__(self):
		return '<Block(%#x - %#x) INS(%d) PREV(%d) NEXT(%d) EXEC(%d) LOOP(%d)\n>' % (
			self.start_addr, self.end_addr, self.ins_count,
			 self.prev_count(),  self.next_count(), self.exec_count, self.loop_count() )



class BlockLoop(object):

	def __init__(self, addr_seq):
		self.addr_seq = addr_seq
		self.count = 1

	def __cmp__(self, obj):

		if obj is self: return 0

		if type(obj) is list:
			return cmp(self.addr_seq, obj)
		if isinstance(obj, self.__class__):
			return cmp(self.addr_seq, obj.addr_seq)
		return cmp(self, obj)
	
	def list_nodes(self, bm):
		for addr in self.addr_seq:
			yield bm.blocks[addr]

	def __repr__(self):
		buf = "loop(%d): " % self.count
		buf += ','.join(hex(i) for i in self.addr_seq[:5])
		if len(self.addr_seq) > 5:
			buf += '.. %d nodes' % len(self.addr_seq)
		return buf

	def __str__(self):
		return ','.join(hex(i) for i in self.addr_seq)





class BBLManager(object):

	def __init__(self):
		self.blocks = {}  # (addr, block)
		self.loops = []
		self.head_block = None


	def load_bbl_info(self, filename):
		blocks = open(filename, 'rb').read().split('####BBL\n')[1:] # skip first ''
		for buf in blocks:
			lines = buf.splitlines()
			start_addr, end_addr, size, ins_count = lines[0].split('\t')
			start_addr = int(start_addr,16)
			end_addr = int(end_addr, 16)
			size = int(size,10)
			ins_count =  int(ins_count,10)

			b = BasicBlock(start_addr, end_addr, size, ins_count)

			# parse ins
			for line in lines[1:]:
				addr, dis = line.split('\t')
				addr = int(addr,16)
				b.ins.append((addr, dis))

			if self.head_block == None: self.head_block = b

			if start_addr not in self.blocks:	
				self.blocks[start_addr] = b
			else:
				# shoud be same block!!
				if self.blocks[start_addr].size != b.size:
					print '='*40 + 'Block collision!'
					print self.blocks[start_addr]
					print '='*40
					print b
					print '='*40

	# ==============================================================================

	'''
	buffered io. faster. 
	'''
	def _buffer_process_addr(self, filename,start_addr = None, end_addr = None, x64=False):
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

			block_addr_seq = struct.unpack(ADDR_FMT*(len(addrs)/ADDR_SIZE), addrs)

			# process blocks
			for addr in block_addr_seq:

				# start at start_addr.
				if start_addr and not started:
					if start_addr != addr:
						continue
					else:
						started = True

				# end at end_addr.
				if end_addr and addr == end_addr:
					break

				yield addr

			if read_size % (BUFSIZE) == 0:
				print '\r%0.2f %% processed\t%s' % (read_size*100.0/filesize, time.asctime())

		f.close()


	'''
	return True if a new loop is appended.
	'''
	def _add_loop(self, loop):
		if loop in self.loops:
			self.loops[self.loops.index(loop)].count += 1
			return False
		else:
			self.loops.append(loop)
			return True  


	'''
	filename: BBL trace file.
	start_addr: start processing at this address. (start_addr will be processed)
	end_addr: stop processing at this address. (end_addr will *not* be processed)
	x64: True for x64 , False for x86
	'''
	def load_bbl_trace(self, filename, start_addr = None, end_addr = None, x64=False):

		prev_block = None

		addr_seq = []
		loops   = []


		for addr in self._buffer_process_addr(filename, start_addr, end_addr, x64):

			cur_block = self.blocks[addr]
			cur_block.exec_count += 1
			if prev_block:				
				cur_block.add_prev(prev_block.start_addr)
				prev_block.add_next(cur_block.start_addr)
			prev_block = cur_block

			#''' 
			# tooooooooooo slow !!!!
			if addr  in  addr_seq:
				# loop found.
				loop_start = addr_seq.index(addr)
				loop = BlockLoop(addr_seq[loop_start: ])
				addr_seq =  addr_seq[ :loop_start]

				if(self._add_loop(loop)):
					for node in loop.list_nodes(self):
						node.add_loop(loop)

			addr_seq.append(addr)
			#'''

		# clear dead block whose exec_count is 0.
		for addr in self.blocks.keys():
			if self.blocks[addr].exec_count == 0:
				self.blocks.pop(addr)

	# ==============================================================================

	def _can_merge_to_prev(self, cur):
		if cur.prev_count() != 1 : return False
		prev = self.blocks[cur.prevs.keys()[0]]
		if prev.next_count() != 1: return False
		return True


	def _merge_to_prev(self, cur):
		prev = self.blocks[cur.prevs.keys()[0]]
		# start not change
		prev.end_addr = cur.end_addr

		prev.size += cur.size
		prev.ins_count += cur.ins_count
		prev.ins += cur.ins

		# prev.prevs not change
		prev.nexts = cur.nexts

		# this shoud be same
		assert prev.exec_count == cur.exec_count

		# fix prev pointer of cur->next.
		for addr in cur.nexts:
			next_block = self.blocks[addr]
			next_block.prevs.pop(cur.start_addr) # remove reference to current block
			next_block.prevs[prev.start_addr] = cur.prevs[prev.start_addr] # add reference to prev block

		self.blocks.pop(cur.start_addr)

	'''
		如果当前结点为前结点是唯一的，且前结点的后结点也是唯一的，那么进行合并。
	'''
	def consolidate_blocks(self):
		print 'before consolidation: %d'%len(self.blocks)

		for addr in self.blocks.keys():
			node =  self.blocks[addr]
			if self._can_merge_to_prev(node):
				self._merge_to_prev(node)

		print 'after consolidation: %d'% len(set(self.blocks.values()))

	# ==============================================================================

	'''
	draw basic block graph with pydot.
	'''
	def display_bbl_graph(self):
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

	'''
	draw basic block graph with IDA pro. much faster!!!
	'''
	def display_bbl_graph_ida(self):
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

				for node in bm.blocks.values():
					for next_addr in node.nexts:
						g.AddEdge(self._nodes.index(node), self._nodes.index(bm.blocks[next_addr]))	

				return True

			def OnGetText(self, node_id):
				node = self[node_id]
				#if self.Count() < 100:
				#	return '%#x(%d) %d\n%s'%(node.start_addr, node.ins_count, node.exec_count, node.ins_str())
				#else:
				#	return '%#x(%d) %d'%(node.start_addr, node.ins_count, node.exec_count)
				return str(self[node_id])

		g = MyGraph(self)
		g.Show()


	def sorted_blocks(self, sorted_by):
		cmp_map = { 
		"prev_count": lambda x,y : x.prev_count() - y.prev_count(),
		"next_count": lambda x,y : x.next_count() - y.next_count(),
		"ins_count": lambda x,y : x.ins_count - y.ins_count,
		"exec_count": lambda x,y : x.exec_count - y.exec_count,
		"prev_mul_next_count": lambda x,y : x.prev_count()*x.next_count() - y.prev_count()*y.next_count(),
		"loop_count":  lambda x,y : x.loop_count() - y.loop_count(),
		}

		if sorted_by not in cmp_map:
			print "sorted by: " + ','.join(cmp_map)
			return

		# descending sort.
		return sorted(self.blocks.values(), cmp_map[sorted_by], reverse=True)


def dump_bm(infofile, tracefile, dumpfile, x64=False):
	global bm
	bm = BBLManager()
	bm.load_bbl_info(infofile)
	bm.load_bbl_trace(tracefile,x64=x64)	
	bm.consolidate_blocks()
	cPickle.dump(bm, open(dumpfile,'wb'))	


def load_bm(dumpfile):
	global bm
	bm = cPickle.load(open(dumpfile,'rb'))
	

def main():
	#load_bm(r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\bm_2.12.3.dump')
	#load_bm(r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\bm_3.09_pack.dump')	
	#load_bm(r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\base64_1.81.dump')
	#bm.display_bbl_graph()
	#bm.display_bbl_graph_ida()
	#bm.sorted_blocks('exec_count')

	dump_bm(r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\BBL.info',
		r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\BBL.trace',
		r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\bm_3.09_pack.dump')


	#cPickle.dump(bm, open('3.09_pack_bbl.dump','wb'))	


if __name__ == '__main__':
	main()

		