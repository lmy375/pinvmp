from pyh import *

import config

def report_html (side_bar, main_content):

	text =  '''
	<!DOCTYPE html>
	<html>
	<head>
		<title>VM Report</title>
		<meta charset="utf-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
		<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
		<link rel="stylesheet" type="text/css" href="semantic/semantic.min.css">
		<link rel="stylesheet" type="text/css" href="css/common.css">

		<script src="semantic/jquery.js"></script>
		<script src="semantic/semantic.min.js"></script>
		<script src="semantic/jquery.address.js"></script>

		<script src="js/common.js"></script>
	</head>
	<body id="report" class="pushable">
		<!-- side_bar begins -->
		%s
		<!-- side_bar ends -->

		<!-- pusher beigns -->
		<div class="pusher">
			<!-- menu begins -->
			<div class="ui fixed inverted blue menu">
			  <div class="header item">
				<div class="ui launch inverted  button ">
			        <i class="sidebar icon"></i>
			        Report
			 	</div>
			  </div>

		<!-- 
		<div class="right menu">
				<div class="ui mobile dropdown link item" tabindex="0">
				  Menu
				  <i class="dropdown icon"></i>
				  <div class="menu" tabindex="-1">
					<a class="item">item1</a>
					<a class="item">item2</a>
				  </div>
				</div>
				<div class="ui dropdown link item" tabindex="0">
				  Courses
				  <i class="dropdown icon"></i>
				  <div class="menu transition hidden" tabindex="-1" style="">
					<a class="item">Petting</a>
					<a class="item">Feeding</a>
					<a class="item">Mind Reading</a>
				  </div>
				</div>
				<a class="item">other</a>
			   </div> 
		-->

			</div>
			<!-- menu ends -->
			<!-- page begins-->
			<div class= "ui page">
			%s
			</div>
			<!-- page ends-->
		</div>
		<!-- pusher ends -->
	</body>
	</html>
	'''% (side_bar, main_content)

	return text


def check_box_h(label, onclick="" ):
	return '''
	<div class="ui toggle checkbox" onclick = '%s'>
		<input type="checkbox">
		<label> %s </label>
	</div>
	''' % (onclick, label)

def item_h(content):
	return '''
	<div class="item">
		%s
	</div>
	''' % content

def menu_h(content):
	return '''
	<div class="menu">
		%s
	</div>
	''' % content



def side_bar_h(content):
	return '''
	<div class="ui blue inverted vertical sidebar menu left">
	    %s
	 </div>
	''' % content

def table_h(head_list, body_list):
	t = table(cl="ui celled striped table")
	head = t << thead() << tr()
	for title in head_list:
		head += th(title)
	body = t << tbody()
	for row in body_list:
		r = body << tr()
		for item in row:
			r += td(item)
	return t.render()

def segment_h(title, content):
	return '''
	<div class="ui stacked segment">
		<a class="ui ribbon label">%s</a>
		%s
	</div>
	''' % (title, content)

def header_h(title):
	return '<h2 class="ui dividing header">%s</h2>\n'% title

def label_h(label):
	return '<span class="ui label">%s</span>' % label

def class_h(cls, content):
	return '<div class="%s"> %s </div>' % (cls, content)


def _pre_process(msg):
	msg = str(msg)
	msg = cgi.escape(msg)

	step = config.REPORT_LINE_LENGTH
	if len(msg) <= step:
		return msg
	return "\n".join(msg[i:i+step] for i in range(0,len(msg),step))

def accordion_h(title, content):
	title = _pre_process(title)
	return '''
	<div class="ui styled accordion">
	  <div class="title">
	    <i class="dropdown icon"></i>
	    %s
	  </div>
	  <div class="content">
	    %s
	  </div>
	</div>
	'''	% (title, content)

def list_h(key_value_list, cls = ""):
	item =  '''
	<div class="item">
	    <div class="content">
	      <div class="header">%s</div>
	      %s
	    </div>
	</div>
	'''
	text = ""
	for k, v in key_value_list:
		text += item % (_pre_process(k), _pre_process(v))

	text = '''
	<div class="ui divided  %s list">
		%s
	</div>
	''' % (cls,text)
	return text

def horizontal_list_h(key_value_list):
	
	return list_h(key_value_list, "horizontal")


def message_h(msg, cls=""):
	return '<div class="ui %s message">\n%s\n</div>\n' % (cls, _pre_process(msg))




def make_side_bar(bm):
	items = ""

	sub_items = ""
	sub_items += item_h(check_box_h('Basic Information', 'toggle("basicinfo")'))
	sub_items += item_h(check_box_h('Instructions', 'toggle("insinfo")'))
	sub_items += item_h(check_box_h('Traces', 'toggle("traceinfo")'))
	sub_items += item_h(check_box_h('Blocks', 'toggle("blockinfo")'))
	sub_items += item_h(check_box_h('Loops', 'toggle("loopinfo")'))
	sub_menu = menu_h(sub_items)

	items += item_h('<b>Overview</b>' + sub_menu)
	
	sub_items = ""
	sub_items += item_h(check_box_h('Level 1', 'toggle("g_level1")'))
	sub_items += item_h(check_box_h('Level 2', 'toggle("g_level2")'))
	sub_items += item_h(check_box_h('Level 3', 'toggle("g_level3")'))
	sub_menu = menu_h(sub_items)

	items += item_h("<b>Execution Graph</b>" + sub_menu)


	addrs = bm.handlers.keys()
	addrs.sort()

	sub_items = ""
	for addr in addrs:
		handler = bm.handlers[addr]
		sub_items += item_h(check_box_h( handler.name, 'toggle("%s")' % handler.name  ))

	sub_menu = menu_h(sub_items)
	items += item_h("<b>Handlers</b>" + sub_menu)

	return side_bar_h(items)


def gen_basicinfo(bm):

	text = ''

	# table_fmt % (name, rows)
	table_fmt = '''
		<div class="ui stacked segment">
			<a class="ui ribbon label">%s</a>
			<table class="ui celled striped table">
				<thead>
					<tr>
						<th>
							Key
						</th>
						<th>
							Value
						</th>
					</tr>
				</thead>
				<tbody>
					%s
					<!-- <tr><td>.text</td><td>200</td> </tr> -->

				</tbody>
			</table>
		</div>
			'''


	non_local = [''] # py 2.x trick  ; in python 3 we use 'nonlocal' keyword.
	def add_item(name, value):
		non_local[0] += '<tr><td>%s</td><td>%s</td> </tr>\n' % (name, value)

	add_item('Binary file', config.EXE_PATH)
	add_item('--------', '--------')
	add_item('Instructions Count', len(bm.instructions))
	add_item('Traces Count', len(bm.traces))
	add_item('Blocks Count', len(bm.blocks))
	add_item('Loops Count', len(bm.loops))
	add_item('--------', '--------')
	add_item('Handlers Count', len(bm.handlers))
	add_item('Handler Traces Count', len(bm.extract_handler_trace()))
	add_item('--------', '--------')
	add_item('Start address', '%#x' % bm.head_addr)
	add_item('Dispatcher address', '%#x' % bm.dispatcher.addr)

	text += table_fmt % ('Basic Information', non_local[0])

	return  class_h('basicinfo', text)


def gen_ins_info(bm):
	text = ''

	table_fmt = '''
	<div class="ui stacked segment">
		<a class="ui ribbon label">%s</a>
		<table class="ui celled striped table">
			<thead>
				<tr>
					<th>
						ID
					</th>
					<th>
						Address
					</th>
					<th>
						Diassembly
					</th>
					<th>
						Hex Bytes
					</th>
					<th>
						Size
					</th>
					<th>
						Execution Count
					</th>
				</tr>
			</thead>
			<tbody>
				%s
				<!-- <tr><td>.text</td><td>200</td> </tr> -->

			</tbody>
		</table>
	</div>
		'''

	count = 1
	rows = ''

	addrs = bm.instructions.keys()
	addrs.sort()

	for addr in addrs:
		
		ins = bm.instructions[addr]

		td_fmt = '<td> %s </td>'
		rows += '<tr>'
		rows += td_fmt % ( count )
		rows += td_fmt % ( '%#x' % ins.addr )
		rows += td_fmt % ( ins.disasm )
		rows += td_fmt % ( ins.bytes.encode('hex').upper() )
		rows += td_fmt % ( ins.size )
		rows += td_fmt % ( len(ins.traces) )
		rows += '</tr>\n'

		count += 1
		if count > config.MAX_ROW:
			break

	text += table_fmt % ('Instructions Information', rows)
	return  class_h('insinfo', text)



def gen_trace_info(bm):
	text = ''

	table_fmt = '''
	<div class="ui stacked segment">
		<a class="ui ribbon label">%s</a>
		<table class="ui celled striped table">
			<thead>
				<tr>
					<th>
						ID
					</th>
					<th>
						Address
					</th>
					<th>
						Diassembly
					</th>
					<th>
						Content
					</th>
				</tr>
			</thead>
			<tbody>
				%s
				<!-- <tr><td>.text</td><td>200</td> </tr> -->

			</tbody>
		</table>
	</div>
		'''

	count = 1
	rows = ''

	for trace in bm.traces:
		
		td_fmt = '<td> %s </td>'
		rows += '<tr>'
		rows += td_fmt % ( count ) # trace.id )
		rows += td_fmt % ( '%#x' % trace.addr )
		rows += td_fmt % ( bm.instructions[trace.addr].disasm )
		rows += td_fmt % ( trace.change_str.replace('\t', '&emsp;'*4) )
		rows += '</tr>\n'

		count += 1
		if count > config.MAX_ROW:
			break

	text += table_fmt % ('Traces Information', rows)
	return  class_h('traceinfo', text)

def gen_block_info(bm):
	text = ''

	table_fmt = '''
	<div class="ui stacked segment">
		<a class="ui ribbon label">%s</a>
		<table class="ui celled striped table">
			<thead>
				<tr>
					<th>
						ID
					</th>
					<th>
						Start Address
					</th>
					<th>
						End Address
					</th>
					<th>
						Instructions Count
					</th>
					<th>
						Execution Count
					</th>
					<th>
						Previous Count
					</th>
					<th>
						Next Count
					</th>
					<th>
						Loop Count
					</th>
				</tr>
			</thead>
			<tbody>
				%s
				<!-- <tr><td>.text</td><td>200</td> </tr> -->

			</tbody>
		</table>
	</div>
		'''

	count = 1
	rows = ''

	addrs = bm.blocks.keys()
	addrs.sort()

	for addr in addrs:

		block = bm.blocks[addr]
		
		td_fmt = '<td> %s </td>'
		rows += '<tr>'
		rows += td_fmt % ( count )
		rows += td_fmt % ( '%#x' % block.start_addr )
		rows += td_fmt % ( '%#x' % block.end_addr )
		rows += td_fmt % ( block.ins_count )
		rows += td_fmt % ( block.exec_count )
		rows += td_fmt % ( block.prev_count )
		rows += td_fmt % ( block.next_count )
		rows += td_fmt % ( block.loop_count )
		rows += '</tr>\n'

		count += 1
		if count > config.MAX_ROW:
			break

	text += table_fmt % ('Blocks Information', rows)
	return  class_h('blockinfo', text)


def gen_loop_info(bm):
	text = ''

	table_fmt = '''
	<div class="ui stacked segment">
		<a class="ui ribbon label">%s</a>
		<table class="ui celled striped table">
			<thead>
				<tr>
					<th>
						ID
					</th>
					<th>
						Loop
					</th>
				</tr>
			</thead>
			<tbody>
				%s
				<!-- <tr><td>.text</td><td>200</td> </tr> -->

			</tbody>
		</table>
	</div>
		'''

	count = 1
	rows = ''

	for loop in bm.loops:
		
		td_fmt = '<td> %s </td>'
		rows += '<tr>'
		rows += td_fmt % ( count )
		rows += td_fmt % ( ' &rarr; '.join('%#x' % addr for addr in loop.addr_seq))
		rows += '</tr>\n'

		count += 1
		if count > config.MAX_ROW:
			break

	text += table_fmt % ('Loops Information', rows)
	return  class_h('loopinfo', text)

def gen_overview(bm):

	text = header_h("Virtualization-obfuscated Binary Analysis Report")
	text += gen_basicinfo(bm)
	text += gen_ins_info(bm)
	text += gen_trace_info(bm)
	text += gen_block_info(bm)
	text += gen_loop_info(bm)

	return text


def gen_graph(bm):

	bm.display_bbl_graph(0, 'svg', 'level1')
	bm.display_bbl_graph(1, 'svg', 'level2')
	bm.display_bbl_graph(2, 'svg', 'level3')
	text = ''
	fmt = '''
		<div class="ui stacked segment">
		<a class="ui ribbon label">Execution Graph (Level %s)</a>
		<img src="image/level%s.svg" width="100%%"></img>
		</div>
	'''
	text += class_h('g_level1', fmt % (1, 1))
	text += class_h('g_level2', fmt % (2, 2))
	text += class_h('g_level3', fmt % (3, 3))

	return  text


def gen_handler(bm):
	text = ''

	fmt = '''
		<div class="ui stacked segment">
		<a class="ui ribbon label">%s</a>
			<div>
			<br>
			%s
			</div>
		</div>
	'''

	addrs = bm.handlers.keys()
	addrs.sort()

	for addr in addrs:
		h_text = ''
		handler = bm.handlers[addr]

		process = lambda x: x.replace('\n', '<br>').replace('\t', '&emsp;'*4)

		title = 'Instructions with Traces' 
		content = process(handler.ins_str_with_trace)
		h_text +=  fmt % (title, content)

		title = 'Instructions without JMP/CALL'
		content = process(handler.ins_str_without_jmp)
		h_text +=  fmt % (title, content)

		title = 'Miasm IR'
		content = process(handler.to_expr())
		h_text +=  fmt % (title, content)	

		title = 'C code'
		content = process(handler.to_c())
		h_text +=  fmt % (title, content)


		text +=  class_h(handler.name, fmt % ('[%s]' % handler.name, h_text))

	return text
	


def gen_report(bm):

	text = ''
	text += gen_overview(bm)
	text += gen_graph(bm)
	text += gen_handler(bm)
	# total = len(self.dbg_infos)
	# count = 0
	# for info in self.dbg_infos:
	# 	text+= info.to_html()
	# 	count+=1
	# 	sys.stdout.write("\rProcessing %d %%..." % (count * 100 /total))
	# sys.stdout.flush()

	text = report_html(make_side_bar(bm), text)

	open(config.REPORT_PATH,'wb').write(text)

def open_report():
	import os
	os.system('%s %s' % (config.BROWSER_PATH, config.REPORT_PATH))


if __name__ == '__main__':
	gen_report()
	open_report()
