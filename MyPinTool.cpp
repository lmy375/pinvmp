
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <map>


/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "Trace tool that logs instruction disassembly and run trace." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
// Global files
/* ===================================================================== */

FILE * tracefile;
FILE * insfile;
FILE * blockfile;

static REG writeea_scratch_reg;


void InitFiles()
{
	tracefile = fopen("bin.trace", "wb");
	insfile = fopen("bin.ins", "wb");
	blockfile = fopen("bin.block", "wb");
	ASSERT(tracefile && insfile && blockfile, "open file failed");
}

void LogTrace(ADDRINT insAddr)
{
	fwrite(&insAddr, sizeof(ADDRINT), 1, tracefile);
}


#if defined(TARGET_IA32)
#define INS_LOG_FORMAT "%#x\t%s\t"
#else
#define INS_LOG_FORMAT "%#lx\t%s\t"
#endif

void LogIns(ADDRINT insAddr, const char *disasm, USIZE insSize, UINT8 *insBytes) {
	fprintf(insfile, INS_LOG_FORMAT, insAddr, disasm);
	for (USIZE i = 0; i < insSize; i++) {
		fprintf(insfile, "%02X", insBytes[i]);
	}
	fprintf(insfile, "\n");
}

void CloseFiles()
{
	fclose(tracefile);
	fclose(insfile);
	fclose(blockfile);
}


/* ===================================================================== */
// Analysis routines
/* ===================================================================== */


int insCount;
VOID InsTrace(ADDRINT insAddr)
{
	insCount++;
	LogTrace(insAddr);
}


ADDRINT filter_ip_low, filter_ip_high;
VOID ImageLoad(IMG img, VOID *v) {
	cerr << "[+] Images loads. " << IMG_Name(img) << endl;
	if (IMG_IsMainExecutable(img)) {
		filter_ip_low = IMG_LowAddress(img);
		filter_ip_high = IMG_HighAddress(img);
		cerr << "[-] Log range:" << StringFromAddrint(filter_ip_low) << "-" << StringFromAddrint(filter_ip_high) << endl;
	}
}

VOID Instruction_addr(INS ins, VOID *v)
{
	ADDRINT ip =  INS_Address(ins);
	if (ip >= filter_ip_low && ip <= filter_ip_high)
	{
		UINT8 ins_buf[0x20];  // instructions won't be too long.
		USIZE ins_size = INS_Size(ins);
		ASSERT(ins_size < sizeof(ins_buf), "so long ins");
		PIN_SafeCopy(ins_buf, (VOID *)ip, ins_size);

		LogIns(ip, INS_Disassemble(ins).c_str(), INS_Size(ins), ins_buf);

		INS_InsertCall(ins, IPOINT_BEFORE,
			(AFUNPTR)InsTrace,
			IARG_INST_PTR,
			IARG_END);
	}
}


UINT32 RegToEnum(REG r) {
#if defined(TARGET_IA32E)
	switch (REG_FullRegName(r)) {
	case REG_GAX: return 0;
	case REG_GCX: return 8;
	case REG_GDX: return 16;
	case REG_GBX: return 24;
	case REG_STACK_PTR: return 32;
	case REG_GBP: return 40;
	case REG_GSI: return 48;
	case REG_GDI: return 56;
	case REG_R8:  return 8 * 8;
	case REG_R9:  return 9 * 8;
	case REG_R10: return 10 * 8;
	case REG_R11: return 11 * 8;
	case REG_R12: return 12 * 8;
	case REG_R13: return 13 * 8;
	case REG_R14: return 14 * 8;
	case REG_R15: return 15 * 8;
	case REG_INST_PTR: return 16 * 8;
	default: return 1024;
	}
#else
	switch (REG_FullRegName(r)) {
	case REG_EAX: return 0;
	case REG_ECX: return 4;
	case REG_EDX: return 8;
	case REG_EBX: return 12;
	case REG_ESP: return 16;
	case REG_EBP: return 20;
	case REG_ESI: return 24;
	case REG_EDI: return 28;
	case REG_EIP: return 32;
	default: return 1024;
	}
#endif
}

// flags
#define IS_VALID    0x80000000
#define IS_WRITE    0x40000000
#define IS_MEM      0x20000000
#define IS_START    0x10000000


struct change {
	uint32_t number;
	uint32_t flags;	
	uint64_t address;
	uint64_t data;
};

static inline void add_change(THREADID tid, uint64_t addr, uint64_t data, uint32_t flags) {
	struct change c;
	c.number = insCount;
	c.flags = flags;
	c.address = addr;
	c.data = data;
	fwrite(&c, sizeof(change), 1, tracefile);
}

static void add_big_change(THREADID tid, uint64_t addr, const void *data, uint32_t flags, size_t size) {
	const UINT64 *v = (const UINT64 *)data;
	while (size >= 8) {
		add_change(tid, addr, *v, flags | 64);
		addr += 8; size -= 8; v++;
	}
	if (size) {
		UINT64 x = *v & ~(~(UINT64)0 << size * 8);
		add_change(tid, addr, x, flags | (size * 8));
	}
}

VOID RecordStart(THREADID tid, ADDRINT ip, UINT32 size){
	insCount++;
	add_change(tid, ip, size, IS_START);
}

VOID RecordRegRead(THREADID tid, UINT32 regaddr, PIN_REGISTER *value, UINT32 size) {
	add_big_change(tid, regaddr, value->byte, 0, size);
}

VOID RecordRegWrite(THREADID tid, UINT32 regaddr, PIN_REGISTER *value, UINT32 size) {
	add_big_change(tid, regaddr, value->byte, IS_WRITE, size);
}

VOID RecordMemRead(THREADID tid, ADDRINT addr, UINT32 size) {
	UINT64 value[16];
	PIN_SafeCopy(value, (const VOID *)addr, size); // Can assume it worked.
	add_big_change(tid, addr, value, IS_MEM, size);
}


static const ADDRINT WRITEEA_SENTINEL = (sizeof(ADDRINT) > 4) ? (ADDRINT)0xDEADDEADDEADDEADull : (ADDRINT)0xDEADDEADul;

ADDRINT RecordMemWrite1(THREADID tid, ADDRINT addr, ADDRINT oldval) {
	return addr;
}
ADDRINT RecordMemWrite2(THREADID tid, ADDRINT addr, UINT32 size) {
	UINT64 value[16];
	PIN_SafeCopy(value, (const VOID *)addr, size); // Can assume it worked.
	add_big_change(tid, addr, value, IS_MEM | IS_WRITE, size);
	return WRITEEA_SENTINEL;
}

VOID Instruction(INS ins, VOID *v) {
	
	ADDRINT address = INS_Address(ins);

	const bool filtered = address < filter_ip_low || filter_ip_high <= address;

	if (filtered) return;


	UINT8 ins_buf[0x20];  // instructions won't be too long.
	USIZE ins_size = INS_Size(ins);
	ASSERT(ins_size < sizeof(ins_buf), "so long ins");
	PIN_SafeCopy(ins_buf, (VOID *)address, ins_size);

	LogIns(address, INS_Disassemble(ins).c_str(), INS_Size(ins), ins_buf);

	INS_InsertCall(
		ins, IPOINT_BEFORE, (AFUNPTR)RecordStart, IARG_THREAD_ID,
		IARG_INST_PTR,
		IARG_UINT32, (UINT32)INS_Size(ins),
		IARG_CALL_ORDER, CALL_ORDER_FIRST,
		IARG_END
	);

	UINT32 rRegs = INS_MaxNumRRegs(ins);
	UINT32 wRegs = INS_MaxNumWRegs(ins);
	UINT32 memOps = INS_MemoryOperandCount(ins);

	// INS_InsertPredicatedCall to skip inactive CMOVs and REPs.

	for (UINT32 i = 0; i < rRegs; i++) {
		REG r = INS_RegR(ins, i);
		if (!REG_is_gr(REG_FullRegName(r))) continue;
		INS_InsertPredicatedCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordRegRead, IARG_THREAD_ID,
			IARG_UINT32, RegToEnum(r),
			IARG_REG_CONST_REFERENCE, r,
			IARG_UINT32, REG_Size(r),
			IARG_END
		);
	}

	for (UINT32 i = 0; i < wRegs; i++) {
		REG r = INS_RegW(ins, i);
		if (!REG_is_gr(REG_FullRegName(r))) continue;
		if (INS_HasFallThrough(ins)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_AFTER, (AFUNPTR)RecordRegWrite, IARG_THREAD_ID,
				IARG_UINT32, RegToEnum(r),
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_END
			);
		}
		if (INS_IsBranchOrCall(ins)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordRegWrite, IARG_THREAD_ID,
				IARG_UINT32, RegToEnum(r),
				IARG_REG_CONST_REFERENCE, r,
				IARG_UINT32, REG_Size(r),
				IARG_END
			);
		}
	}

	if (INS_Mnemonic(ins) == "XSAVE") {
		// Still not supported. 
		return;
	}

	for (UINT32 i = 0; i < memOps; i++) {
		if (INS_MemoryOperandIsRead(ins, i)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_THREAD_ID,
				IARG_MEMORYOP_EA, i,
				IARG_MEMORYREAD_SIZE,
				IARG_END
			);
		}

		if (INS_MemoryOperandIsWritten(ins, i)) {
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite1, IARG_THREAD_ID,
				IARG_MEMORYOP_EA, i,
				IARG_REG_VALUE, writeea_scratch_reg,
				IARG_RETURN_REGS, writeea_scratch_reg,
				IARG_END
			);
			if (INS_HasFallThrough(ins)) {
				INS_InsertPredicatedCall(
					ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite2, IARG_THREAD_ID,
					IARG_REG_VALUE, writeea_scratch_reg,
					IARG_MEMORYWRITE_SIZE,
					IARG_RETURN_REGS, writeea_scratch_reg,
					IARG_END
				);
			}
			if (INS_IsBranchOrCall(ins)) {
				INS_InsertPredicatedCall(
					ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite2, IARG_THREAD_ID,
					IARG_REG_VALUE, writeea_scratch_reg,
					IARG_MEMORYWRITE_SIZE,
					IARG_RETURN_REGS, writeea_scratch_reg,
					IARG_END
				);
			}
		}
	}


}


VOID BblTrace(ADDRINT addr)
{
	fwrite(&addr, sizeof(ADDRINT), 1, blockfile);
}

VOID Trace(TRACE trace, VOID *v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		ADDRINT addr = BBL_Address(bbl);
		if (addr >= filter_ip_low && addr <= filter_ip_high) {
			BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BblTrace,
				IARG_UINT32, addr,
				IARG_END);
		}
	}
}

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	cerr << "[+] Thread " << threadIndex << " starts" << endl;
}



void Init()
{
	InitFiles();

	

}


VOID Fini(INT32 code, VOID *v)
{
	CloseFiles();
	cerr << "\n[+] "<< insCount <<" instructions logged." << endl;
	cerr << "=============================================" << endl;
	cerr << "<< END >>" << endl;
}


/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
	Init();
	
	writeea_scratch_reg = PIN_ClaimToolRegister();
	if (!REG_valid(writeea_scratch_reg)) {
		fprintf(stderr, "[!] Failed to claim a scratch register.\n");
		return 1;
	}

	IMG_AddInstrumentFunction(ImageLoad, 0);
	INS_AddInstrumentFunction(Instruction, 0);
	TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
