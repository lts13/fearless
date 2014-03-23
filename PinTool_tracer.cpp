/*! 
 *  This program will trace execution and log to a file.
 *  Takes advantage of INTEL Pin's intelligence.
 *  It doesn't need to know in advance the functions but
 *  is capable to detect when a CALL is executed instead :)
 *  
 *  @note: I'm not interested in calls to system DLLs, so
 *  record range for every loaded module (imgLoad_cb) 
 *  and check if EIP is within range.
 *  At load time, check if their images' path start with 
 *  "C:\WINDOWS\SYSTEM32"
 *  If so, exclude them from list of application modules
 */

#include <stdio.h>
#include <iostream>
#include <map>			// used for... maps:)
#include <string.h>		// used for strncmp()
#include <algorithm>	// used for find()
#include "pin.H"


using std::vector;
using std::find;

/* Global Variables */
struct moduledata_t
{
	BOOL excluded;
	ADDRINT begin;
	ADDRINT end;
};

typedef std::map<string, moduledata_t> modmap_t;

FILE* LogFile;
vector<ADDRINT> loggedAddresses;
modmap_t mod_data;
PIN_LOCK lock;



/* Command Line stuff */
KNOB<BOOL> KnobLogArgs(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "log call arguments ");
KNOB<BOOL> KnobLogIns(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "log all instructions");
KNOB<BOOL> KnobLogBB(KNOB_MODE_WRITEONCE, "pintool", "bb", "0", "log all basic blocks");
KNOB<BOOL> KnobLogHit(KNOB_MODE_WRITEONCE, "pintool", "hit", "0", "log each function only once");



/* ================================================================================= */
/* Finish and cleanup functions.													 */
/* ================================================================================= */
void Fini(INT32 code, void *v)
{
	// cleanup
	fprintf(LogFile, "\n---------------- End of trace ----------------\n");
	fflush(LogFile);
	fclose(LogFile);
	cout << endl << "[*] Log File closed" << endl;
}


/* ================================================================================= */
/* AUXILIARY functions.																 */
/* @todo: put this in a separate file, maybe?										 */
/* ================================================================================= */

const char* StripPath(const char *path)
{
	const char *file = strrchr(path, '\\');	// backward slash (for windows paths)
	
	if(file)
		return file + 1;
	else
		return path;
}


BOOL withinExcludedModules(ADDRINT ip)
{
	for(modmap_t::iterator it = mod_data.begin(); it != mod_data.end(); ++it)
	{
		if(it->second.excluded == FALSE) continue;

		/* Is the EIP value within the range of any excluded module? */
		if(ip >= it->second.begin && ip <= it->second.end) return TRUE;
	}

	return FALSE;
}


BOOL alreadyLoggedAddresses(ADDRINT ip)
{
	if(find(loggedAddresses.begin(), loggedAddresses.end(), ip) != loggedAddresses.end())
	{
		// item IS IN vector
		return true;
	}
	else
	{
		// item is NOT in vector. Push it for the next time.
		loggedAddresses.push_back(ip);
		return false;
	}
}


/* ================================================================================= */
/* This is called every time a MODULE (dll, etc.) is LOADED							 */
/* ================================================================================= */
void imageLoad_cb(IMG Img, void *v)	// Analysis component (Execution time)
{
	const char* imageName = IMG_Name(Img).c_str();
	ADDRINT lowAddress = IMG_LowAddress(Img);
	ADDRINT highAddress = IMG_HighAddress(Img);

	if(IMG_IsMainExecutable(Img))	
	{
		fprintf(LogFile, "[-] Analysing main image: %s\n", StripPath(IMG_Name(Img).c_str()));
		fprintf(LogFile, "[-] Main image memory base:\t %08x\n", lowAddress);
		fprintf(LogFile, "[-] Main image memory end:\t %08x\n", highAddress);
	} else {
		fprintf(LogFile, "[-] Loaded module:\t %s\n", imageName);

		if(strncmp(imageName, "C:\\WINDOWS", 10) == 0)
		{
			fprintf(LogFile, "[!] Filtered %s\n", imageName);
			// I'm not interested on code within these modules
			mod_data[imageName].excluded = TRUE;
			mod_data[imageName].begin = lowAddress;
			mod_data[imageName].end = highAddress;
		}
		
		fprintf(LogFile, "[-] Module base:\t %08x\n", lowAddress);
		fprintf(LogFile, "[-] Module end:\t %08x\n", highAddress);
		fflush(LogFile);
	}
}


/* ================================================================================= */
/* Log some information related to THREAD execution									 */
/* ==========================================f======================================= */
void threadStart_cb(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	PIN_GetLock(&lock, threadIndex + 1);
	fprintf(LogFile, "[*] THREAD 0x%02x STARTED. Flags: %x\n", (int)threadIndex, flags);
	fflush(LogFile);
	PIN_ReleaseLock(&lock);
}


void threadFinish_cb(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	PIN_GetLock(&lock, threadIndex + 1);
	fprintf(LogFile, "[-] THREAD 0x%02x FINISHED. Code: %d\n", (int)threadIndex, code);
	fflush(LogFile);
	PIN_ReleaseLock(&lock);
}


/* ================================================================================= */
/* Log the basic block we are in (within a function)								 */
/* ================================================================================= */
void LogBasicBlock(ADDRINT ip)
{
	// NOTE: Maybe inefficient here
	if(withinExcludedModules(ip))
		return;

	fprintf(LogFile, "  loc_%p:\n", ip);
}


/* ================================================================================= */
/* Log every INSTRUCTION hit														 */
/* ================================================================================= */
void LogInstruction(ADDRINT ip, const char* disasm_string) 
{
	// NOTE: Maybe inefficient here
	if(withinExcludedModules(ip))
		return;

	fprintf(LogFile, "\t%p %s\n", ip, disasm_string);
	fflush(LogFile);
}


void instruction_cb(INS ins, void *v)
{
	// Insert a call to printip before every instruction, and pass it the IP
	// This is better placed inside a trace
    INS_InsertCall(
					ins, 
					IPOINT_BEFORE, 
					(AFUNPTR)LogInstruction, 
					IARG_INST_PTR,
					IARG_PTR,
					"test",
					IARG_END
					);
}


/* ================================================================================= */
/* CALLBACKS implementing the actual LOGGING										 */
/* ================================================================================= */
void LogCall(ADDRINT ip)
{
	/* -hit switch present: log only once (hit) */
	if(KnobLogHit.Value() && alreadyLoggedAddresses(ip))
		return;
		
	if (withinExcludedModules(ip))
		return;

	string nameFunc = "";

	try 
	{
		string nameFunc = RTN_FindNameByAddress(ip);
	} 
	catch (int e)
	{
		cout << "Exception Nr. " << e << endl;
	}


	if(nameFunc == "" || nameFunc == "unnamedImageEntryPoint")
	{
		UINT32 *CallArg = (UINT32 *)ip;
		/* @note: $ has no meaning, just a random token */
		fprintf(LogFile, "$ Function %p called\n", CallArg);
	} else {
		/* Function name has been successfully resolved */
		fprintf(LogFile, "$ Function %s called\n", nameFunc);
	}
}


void LogCallAndArgs(ADDRINT ip, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
	/* -hit switch present: log only once (hit) */
	if(KnobLogHit.Value() && alreadyLoggedAddresses(ip))
		return;
	else if (withinExcludedModules(ip))
		return;
	else
	{
		UINT32 *CallArg = (UINT32 *)ip;
		/* @note: $ has no meaning, just a random token */
		fprintf(LogFile, "$ Function %p called with args: (%08x, %08x, %08x)\n", CallArg, arg0, arg1, arg2);
	}
}


/*! The following two are some kind of "execution hubs"
 *  At the end they call LogCall*()
 */
void LogIndirectCall(ADDRINT target, BOOL taken)
{
	/* -hit switch present: log only once (hit) */
	if(KnobLogHit.Value() && alreadyLoggedAddresses(target))
		return;
	else if(!taken)
		return;
	else if(withinExcludedModules(target))
		return;
	else
		LogCall(target);
}


void LogIndirectCallAndArgs(ADDRINT target, BOOL taken, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
	/* -hit switch present: log only once (hit) */
	if(KnobLogHit.Value() && alreadyLoggedAddresses(target))
		return;
	else if(!taken)
		return;
	else if(withinExcludedModules(target))
		return;
	else
		LogCallAndArgs(target, arg0, arg1, arg2);
}


/*! This identifies different types of CALL methods
 *  and its callbacks log the functions hit
 *  NOTE: These are all instrumentation functions (JIT), 
 *  they just point to the analysis ones
 */
void Trace(TRACE trace, void *v)
{
	/* Do I want to log function arguments as well? */
	const BOOL log_args	= KnobLogArgs.Value();
	const BOOL log_bb	= KnobLogBB.Value();
	const BOOL log_ins	= KnobLogIns.Value();


	/* Iterate through basic blocks */
	for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		/* Instrument at basic block level? */
		if(log_bb)
		{
			/* instrument BBL_InsHead to write "loc_XXXXX", like in IDA Pro */
			INS head = BBL_InsHead(bbl);
			INS_InsertCall(head, IPOINT_BEFORE, AFUNPTR(LogBasicBlock), IARG_INST_PTR, IARG_END);
		}

		if(log_ins)
		{
			/* log EVERY instruction. This kills performance of course */
			for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				INS_InsertCall(ins, 
								IPOINT_BEFORE, 
								AFUNPTR(LogInstruction), 
								IARG_INST_PTR, 
								IARG_PTR, 
								INS_Disassemble(ins).c_str(), 
								IARG_END
								);
			}
		}

		/* ===================================================================================== */
		/* Code to instrument the events at the end of a BBL (execution transfer)				 */
		/* Checking for calls, etc.																 */
		/* ===================================================================================== */
		INS tail = BBL_InsTail(bbl);

		if(INS_IsCall(tail))
		{
			/* True if ins is a CALL instruction */
			if(INS_IsDirectBranchOrCall(tail))
			{
				/* True if the target address is EIP + offset or an immediate */
				const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);

				if(log_args)
				{
					INS_InsertPredicatedCall(
											tail,
											IPOINT_BEFORE,
											AFUNPTR(LogCallAndArgs),		// Fn to jmp to
											IARG_ADDRINT,					// "target"'s type
											target,							// The XXX in "CALL XXX" :)
											IARG_FUNCARG_ENTRYPOINT_VALUE,	// Arg_0 value
											0,
											IARG_FUNCARG_ENTRYPOINT_VALUE,	// Arg_1 value
											1,
											IARG_FUNCARG_ENTRYPOINT_VALUE,	// Arg_2 value
											2,
											IARG_END						// No more args
											);
				}
				else
				{
					INS_InsertPredicatedCall(
											tail,
											IPOINT_BEFORE,
											AFUNPTR(LogCall),		// Fn to jmp to
											IARG_ADDRINT,			// "target"'s type
											target,					// The XXX in "CALL XXX" :)
											IARG_END				// No more args
											);
				}

			}
			else
			{
				/* INS_IsBranchOrCall == True. Includes both direct and indirect types */
				if(log_args)
				{
					INS_InsertCall(
									tail,
									IPOINT_BEFORE,
									AFUNPTR(LogIndirectCallAndArgs),	// Fn to jmp to
									IARG_BRANCH_TARGET_ADDR,			// "target"'s type
									IARG_BRANCH_TAKEN,
									IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_0 value
									0,
									IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_1 value
									1,
									IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_2 value
									2,
									IARG_END							// No more args
									);
				}
				else
				{
					INS_InsertCall(
									tail,
									IPOINT_BEFORE,
									AFUNPTR(LogIndirectCall),	// Fn to jmp to
									IARG_BRANCH_TARGET_ADDR,	// Well... target address? :)
									IARG_BRANCH_TAKEN,			// Non zero if branch is taken
									IARG_END					// No more args
									);
				}
			}
		} // end "if INS_IsCall..."
		else
		{
			/* INS_IsCall == False. Other forms of execution transfer */

			RTN rtn = TRACE_Rtn(trace);
			// Trace jmp into DLLs (.idata section that is, imports)
			if(RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) && SEC_Name(RTN_Sec(rtn)) == ".idata")
			{
				if(log_args)
				{
					INS_InsertCall(
									tail,
									IPOINT_BEFORE,
									AFUNPTR(LogIndirectCallAndArgs),	// Fn to jmp to
									IARG_BRANCH_TARGET_ADDR,
									IARG_BRANCH_TAKEN,
									IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_0 value
									0,
									IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_1 value
									1,
									IARG_FUNCARG_ENTRYPOINT_VALUE,		// Arg_2 value
									2,
									IARG_END							// No more args
									);
				}
				else
				{
					INS_InsertCall(
									tail,
									IPOINT_BEFORE,
									AFUNPTR(LogIndirectCall),
									IARG_BRANCH_TARGET_ADDR,
									IARG_BRANCH_TAKEN,
									IARG_END
									);
				}
			}
		}
	} // end "for bbl..."
} // end "void Trace..."


/* Help message */
INT32 Usage()
{
	cout << "--------------------------------------------------------------------------------------" << endl;
	cout << "The awesome PinTracer :)" << endl;
	cout << "Log addresses of every call ever made. Used in differential debugging." << endl;
	cout << "--------------------------------------------------------------------------------------" << endl;

	cout << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}


/* Main function - initialize and set instrumentation callbacks */
int main(int argc, char *argv[])
{
	/* Initialize Pin with symbol capabilities */
	PIN_InitSymbols();	
	
	if(PIN_Init(argc, argv)) return Usage();

	// const BOOL log_ins = KnobLogIns.Value(); // Log all instructions?

	LogFile = fopen("tracefile.txt", "w");
	if(LogFile == NULL)
	{
		cout << "[!] Something went wrong opening the log file..." << endl;
		return -1;
	} else {
		cout << "[*] Log file opened for writing..." << endl << endl;
	}


	/* Set callbacks
	if(log_ins)
	{
		INS_AddInstrumentFunction(instruction_cb, 0);		// instruction level
	} */
	TRACE_AddInstrumentFunction(Trace, 0);				// basic block analysis
	IMG_AddInstrumentFunction(imageLoad_cb, 0);			// image activities
	PIN_AddThreadStartFunction(threadStart_cb, 0);		// thread start
	PIN_AddThreadFiniFunction(threadFinish_cb, 0);		// thread end

	PIN_AddFiniFunction(Fini, 0);

	fprintf(LogFile, "---------------- Starting Pin Tracer ----------------\n");

	/* It never returns, sad :) */
	PIN_StartProgram();

	return 0;
}
