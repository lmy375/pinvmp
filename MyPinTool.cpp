
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <map>


/* ================================================================== */
// Global variables 
/* ================================================================== */

UINT64 insCount = 0;        //number of dynamically executed instructions
UINT64 traceCount = 0;
UINT64 bblCount = 0;        //number of dynamically executed basic blocks
UINT64 threadCount = 0;     //total number of threads, including main thread

FILE * bblInfoFile;  
FILE * bblTraceFile; // bbl execute trace.

FILE * insInfoFile;
FILE * insTraceFile; // ins execute trace.

#define NUM_BUF_PAGES 1024
BUFFER_ID bblTraceBufId;

std::ostream * out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<BOOL>   KnobLogIns(KNOB_MODE_WRITEONCE, "pintool",
	"logins", "0", "log instruction execution trace.");




/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */


VOID BblTrace(ADDRINT bblAddr)
{
    bblCount++;
	//fprintf(bblTraceFile, "%#x\n", bblAddr);	
	fwrite(&bblAddr, sizeof(ADDRINT), 1, bblTraceFile);
}


VOID TraceInfo(ADDRINT traceAddr, UINT32 traceSize, UINT32 numBbl, UINT32 numIns)
{
	traceCount++;
	//fprintf(tracefile, "==== Trace (%#x): size %d, BBL: %d, INS: %d\n", traceAddr, traceSize, numBbl, numIns);
}

VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
	IMG img = IMG_FindByAddress(TRACE_Address(trace));
	if (IMG_Valid(img) && IMG_IsMainExecutable(img) )
	{
		TRACE_InsertCall(trace, IPOINT_ANYWHERE, (AFUNPTR)TraceInfo,
			IARG_ADDRINT, TRACE_Address(trace),
			IARG_UINT32, TRACE_Size(trace),
			IARG_UINT32, TRACE_NumBbl(trace),
			IARG_UINT32, TRACE_NumIns(trace),
			IARG_END);
		/*
		fprintf(tracefile, "Trace (%#x - %#x ) %d, BBL: %d, INS: %d\n",
			INS_Address(BBL_InsHead(TRACE_BblHead(trace))), 
			INS_Address(BBL_InsTail(TRACE_BblTail(trace))),
			TRACE_Size(trace), TRACE_NumBbl(trace), TRACE_NumIns(trace));
		*/
		for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			ADDRINT bblstart = BBL_Address(bbl);
			ADDRINT bblend  = INS_Address(BBL_InsTail(bbl));
			UINT32 bblsize = BBL_Size(bbl);
			UINT32 numIns = BBL_NumIns(bbl);


			// Log BBL execute trace.
			BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BblTrace, 
				IARG_UINT32, bblstart,
				IARG_END);

			// Log BBL info.
			#if defined(TARGET_IA32)
			fprintf(bblInfoFile, "####BBL\n%#x\t%#x\t%d\t%d\n", 
			#else
			fprintf(bblInfoFile, "####BBL\n%#lx\t%#lx\t%d\t%d\n", 
			#endif
				bblstart,
				bblend,
				bblsize, numIns);

			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
			#if defined(TARGET_IA32)
				fprintf(bblInfoFile, "%#x\t%s\n", 
			#else
				fprintf(bblInfoFile, "%#lx\t%s\n", 
			#endif
					INS_Address(ins), INS_Disassemble(ins).c_str());
			}

		}
	}
}

/* Ins analysis */

VOID InsCount(ADDRINT ip, std::string *dis)
{
	insCount++;
	//fprintf(tracefile, "%#x\t%s\n", ip, (*dis).c_str());
}

VOID InsTrace(ADDRINT insAddr)
{
	insCount++;
	fwrite(&insAddr, sizeof(ADDRINT), 1, insTraceFile);
}

VOID Instruction(INS ins, VOID *v)
{
	IMG img = IMG_FindByAddress(INS_Address(ins));
	if (IMG_Valid(img) && IMG_IsMainExecutable(img))
	{

		if (KnobLogIns.Value()) {
			/* just same format as block info. */
		#if defined(TARGET_IA32)
			fprintf(insInfoFile, "####BBL\n%#x\t%#x\t%d\t%d\n%#x\t%s\n",
		#else
			fprintf(bblInfoFile, "####BBL\n%#lx\t%#lx\t%d\t%d\n%#lx\t%s\n",
		#endif
				INS_Address(ins),
				INS_Address(ins),
				INS_Size(ins), 1,
				INS_Address(ins), INS_Disassemble(ins).c_str());
		}

		INS_InsertCall(ins, IPOINT_BEFORE, 
			(AFUNPTR)InsCount, 
			IARG_ADDRINT, INS_Address(ins), 
			IARG_PTR, new string(INS_Disassemble(ins)), 
			IARG_END);

		if (KnobLogIns.Value()) {
			INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR)InsTrace,
				IARG_INST_PTR,
				IARG_END);
		}

	}
}

//////////////////////////////////////////////////////////////////
// BBL insert buf not supported !!!
// so this is not used
/*
PIN_LOCK fileLock;

VOID * BufferFull(BUFFER_ID id, THREADID tid, const CONTEXT *ctxt, VOID *buf,
	UINT64 numElements, VOID *v)
{
	PIN_GetLock(&fileLock, 1);
	fwrite(buf, sizeof(ADDRINT), numElements, bblTraceFile);
	PIN_ReleaseLock(&fileLock);
	return buf;
}
*/

//////////////////////////////////////////////////////////////////

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	threadCount++;
}


VOID Fini(INT32 code, VOID *v)
{
	fclose(bblInfoFile);
	fclose(bblTraceFile);

	if (KnobLogIns.Value()) {
		fclose(insInfoFile);
		fclose(insTraceFile); 
	}
	
	*out << "===============================================" << endl;
	*out << "MyPinTool analysis results (main exe): " << endl;
	*out << "Number of instructions: " << insCount << endl;
	*out << "Number of trace: " << traceCount << endl;
	*out << "Number of basic blocks: " << bblCount << endl;
	*out << "Number of threads: " << threadCount << endl;
	*out << "===============================================" << endl;
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
	bblInfoFile = fopen("BBL.info", "wb");
	bblTraceFile = fopen("BBL.trace", "wb");


	if (KnobLogIns.Value()) {
		insInfoFile = fopen("INS.info", "wb");
		insTraceFile = fopen("INS.trace", "wb");
	}




	//bblTraceBufId = PIN_DefineTraceBuffer(sizeof(ADDRINT), NUM_BUF_PAGES,
	//	BufferFull, 0);


    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}

	// Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);

	INS_AddInstrumentFunction(Instruction, 0);

    // Register function to be called for every thread before it starts running
    PIN_AddThreadStartFunction(ThreadStart, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
