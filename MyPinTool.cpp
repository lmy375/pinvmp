
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

void InitFiles()
{
	tracefile = fopen("bin.trace", "wb");
	insfile = fopen("bin.ins", "wb");
	ASSERT(tracefile && insfile, "open file failed");
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
	cerr << "Images loads. " << IMG_Name(img) << endl;
	if (IMG_IsMainExecutable(img)) {
		filter_ip_low = IMG_LowAddress(img);
		filter_ip_high = IMG_HighAddress(img);
		cerr << "Log range:" << StringFromAddrint(filter_ip_low) << "-" << StringFromAddrint(filter_ip_high) << endl;
	}
}

VOID Instruction(INS ins, VOID *v)
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



VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	cerr << "Thread " << threadIndex << " starts" << endl;
}


void Init()
{
	InitFiles();
}


VOID Fini(INT32 code, VOID *v)
{
	CloseFiles();
	cerr << insCount << "instructions logged." << endl;
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

	IMG_AddInstrumentFunction(ImageLoad, 0);
	INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
