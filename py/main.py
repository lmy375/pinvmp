
import bbl_manager
import config
import report

import os

def main():
    # Change work folder.
    os.chdir(config.WORK_PATH)

    print '[*] Target: %s' % config.EXE_PATH
    print '----- STEP 1 -----'
    print '[*] Running PinTool ...'
    print '#'*80

    os.system(config.PIN_CMD)

    print '#'*80

    print '[*] Pin instrument finished.' 

    global bm
    bm = bbl_manager.BBLManager()


    print '----- STEP 2 -----'
    # Load instructions.
    bm.load_ins_info(config.INS_PATH)

    print '----- STEP 3 -----'
    # Load trace.
    bm.load_trace(config.TRACE_PATH, config.START_ADDR, config.END_ADDR)

    print '----- STEP 4 -----'
    # Generate execution graph.
    bm.consolidate_blocks()

    print '----- STEP 5 -----'
    bm.detect_handlers()

    print '----- STEP 6 -----'
    print '[*] Generating report ....'
    report.gen_report(bm)  
    print '[*] Report generated.'

    # report.open_report()


if __name__ == '__main__':
    # try:
    main()
    # except Exception, e:
    #     print '[!] Fatal Error %s' % e
    
    # global bm
    # bm =  bbl_manager.BBLManager()
    # bm.load_ins_info(r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\bin.ins')
    # bm.load_trace(r'D:\papers\pin\pin-3.2-81205-msvc-windows\source\tools\MyPinTool\bin.trace',
    #     # start_addr=0x401000, end_addr=0x40127C) # allop
    #     start_addr=0x401000, end_addr=0x0040101A ) # base64
    # # bm.load_trace('../bin.block')      
    # bm.consolidate_blocks()
    # # cPickle.dump(bm, open('test.dump','wb')) 
    # bm.display_bbl_graph()
    # # bm.display_bbl_graph_ida()

    # bm.detect_handlers() 
    # bm.dump_handlers()


    # report.gen_report(bm)
    # report.open_report()