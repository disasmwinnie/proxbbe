/**
 * @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
 * @file exec_tracer.h
 *
 * Contains the main logic of ProXBBE's tracer tool, including usage of PIN's
 * instrumentation routines.
 *
 */
#include "pin.H"
#include <iostream>
#include <cassert>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <list>
#include <algorithm>
#include <typeinfo>
#include<unistd.h>
#include "ExecState.h"
#include "InsState.h"
#include "SyscallState.h"
#include "base64.h"

using namespace std;

/** Warn message if a socketpair() syscall is found during runtime */
static const string socketpair_msg = "!!![WARN]: socketpair(), pipe() or \
pipe2() syscall sighted. \
This propably means that multiple processes are involved in receiving and \
parsing packets. This _could_ mean the result will malformed. Please double \
check with strace if the right sockets receive the packet\n[!!!]\n";

/**
 * Warn message if a recvmsg() call with multiple iovec structures is called
 * (which is not supported at the moment.
 */
static const string recvmsg_iovec = "!!![WARN]: detected a recvmsg() syscall \
                                    using multiple iovec structures. This is \
                                    not support by ProXBBE. Only data of one \
                                   iovec structure will be recorded. Resulting \
                                   return value will be wrong! Adjust it by \
                                   hand.\n[!!!]\n";

static const ADDRINT PIPE_SYSCALL = 22; /**< Number of pipe()-syscall */
static const ADDRINT PIPE2_SYSCALL = 293; /**< Number of pipe2()-syscall */
static const ADDRINT SOCKETPAIR_SYSCALL = 53; /**< Number of socketpair()-syscall */
static const ADDRINT SOCKET_SYSCALL = 41; /**< Number of socket()-syscall */
static const ADDRINT OPEN_SYSCALL = 2; /**< Number of open()-syscall */
static const ADDRINT CLOSE_SYSCALL = 3; /**< Number of close()-syscall */
static const ADDRINT READ_SYSCALL = 0;  /**< Number of read()-syscall */
static const ADDRINT RECVFROM_SYSCALL = 45; /**< Number of recvfrom()-syscall */
static const ADDRINT RECVMSG_SYSCALL = 47; /**< Number of recvmsg()-syscall */


BOOL socket_called = false; /**< Holds state between pre-syscall and
                              after-syscall pin-callbacks. Only way for
                              after-syscall to know if socket() was called. */

BOOL rec_in_progress = false; /**< Used as a helper to hold state between
                                before- and after-syscall callback. Used for
                               after-syscall to retrieve return value of
                              recv*()- or read()-syscalls */

list<ADDRINT> socket_fds; /**< Holds valid sockets/file descriptors. */

ofstream trace; /**< Output file for trace */

list<UINT32> running_threads; /**< Currently running thread IDs. */

/**
 * Holds the trace for corresponding thread and other thread specific
 * information.
 */
struct ThreadTrace
{
  list<ExecState*> exec_states; /**< Trace, consisting of execution states */
  list<pair<string, pair<string, uint32_t> > >* ops = NULL; /**< Temporary data
                                                              structure to hold
                                                              operands. */
  SyscallState* tmp_syscall_state = NULL; /**< Temporary data structure to hold
                                            a syscall state obj between
                                            before-after callbacks. */
  /**
   * Destructor, iterates over all pointer in exec_states list and deletes them.
   * the truple/list "ops" doesn't need deletion since it is deleted in
   * ExecState.
   */
  ~ThreadTrace()
  {
    for( list<ExecState*>::iterator es_it = exec_states.begin();
            es_it != exec_states.end(); ++es_it )
    {
      ExecState *exec_state = *es_it;
      delete exec_state;
    }
  }
};

static TLS_KEY tls_key; /**< PIN's internal helper to read/write thread specific
                          data, in this case ThreadData */

/* Commandline switches. */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		"o", "trace_output-", "specify output file name"); /**< CMD-line switch for
                                                         output file. */
KNOB<string> KnobFileDescriptors(KNOB_MODE_APPEND, "pintool",
        "fds", "", "specify file descriptors to track beforehand"); /**< CMD-line
                                                                      switch for
                                                                      sockets. */
/* Commandline switches. */

PIN_LOCK lock; /**< PIN's mechanism for locking. Synchronized access between
                 threads */

BOOL trace_running = false; /**< Used to determine whether to start PIN
                              instrumentation. */

static const bool debug_mode = true; /**< Activates verbose logging. */

/**
 * Helper for tokenizing string by comma.
 * @param fds comma separated string with pre-defined file descriptors
 * @return list with file descriptors as strings
 */
list<string>
split_fds(string fds);

/**
 * Processes the recvmsg pointer and returns a SyscallState obj made from
 * result. The recvmsg does not get buf and its len as params but uses the
 * msghdr, which is defined as follows.
 *
 *   struct msghdr {
 *       void         *msg_name;
 *       socklen_t     msg_namelen;
 *       struct iovec *msg_iov;
 *       size_t        msg_iovlen;
 *       void         *msg_control;
 *       size_t        msg_controllen;
 *       int           msg_flags;
 *   };
 *
 * We are only interested in iovec structure, which is defined in the following
 * way:
 *
 *  struct iovec {
 *      void  *iov_base;
 *      size_t iov_len;
 *  };
 * We extract the pointer to this structure, the msghdr.msg_iov and
 * msghdr.msg_iovlen. Latter states how much elements the msg_iov array consists
 *  of. At the moment ProXBBE only supports one element arrays.
 *  @param msghdr_ptr pointer to msghdr_ptr struct, received by a recvmsg() call
 *  @param buf_addr buffer pointer to store result from msghdr struct
 *  @param buf_size pointer to buffer length to store the result
 */
VOID
handle_recvmsg(void *msghdr_ptr, ADDRINT* buf_addr, ADDRINT* buf_size);

/**
 * Wrapper around PIN's LOG(), which only prints in case DEBUG mode is active.
 * @param msg log message
 */
VOID
DBG(string msg);

/**
 * Usage message, in case the tool is used incorrectly.
 * @return status code
 */
INT32
usage();

/**
 * Writes results (traces) of every thread into an own jsonl file.
 *
 * PIN callback, executed at after a process has finished.
 * @param code
 * @param v
 */
VOID
p_finished(const INT32 code, VOID* v);

/**
 * Checks if syscall relevant i.e. syscall receives network packets or opens/
 * closes a socket. If this requirement is fullfilled it parses the cmd line
 * arguments of the syscall and saves into the trace.
 * If a socket() or close() syscall happend, then the state is adjustes (which
 * holds a list of active sockets).
 *
 * PIN callback, executed before a syscall happens.
 * @param tid
 * @param ctxt
 * @param std
 * @param v
 */
VOID
syscall_handler_before(THREADID tid, CONTEXT* ctxt,
		SYSCALL_STANDARD std, VOID* v);

/**
 * Parses the return argument of a relevant syscall. If it is a socket() call
 * then the return value is socket/file descriptor saved in a list. If it is a
 * open()- or recv*()-syscall then the return value is the amount of received
 * bytes, which is stored in the trace.
 *
 * PIN callback, executed before a syscall happens.
 * @see syscall_handler_before()
 * @param tid
 * @param ctxt
 * @param sctd
 * @param v
 */
VOID
syscall_handler_after(THREADID tid, CONTEXT* ctxt,
		SYSCALL_STANDARD sctd, VOID* v);

/**
 * Extracts information about an instruction to be executed. This includes
 * the instruction category, operands and the whole CPU state. Note: the method
 * has a lot of callbacks which collect all the mentioned information. This
 * method determines which of them should be called, e.g., rec_imm (record
 * immediate) method should only be called if an immediate operand is available.
 *
 * PIN callback, executed before an Assembly instruction is executed.
 * @param trace
 * @param v
 */
VOID
instruction_trace(const TRACE trace, VOID* v);

/**
 * Initializes data structures needed to record a thread specific execution
 * trace.
 *
 * PIN callback, executed before a thread is started.
 * @param tid
 * @param ctxt
 * @param flags
 * @param v
 */
VOID
thread_started(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v);

/**
 * Unregisters the running thread from the ProXBBE tool, so no further
 * information is saved in this thread specific trace.
 *
 * PIN callback, executed before a thread is finished.
 * @param tid
 * @param ctxt
 * @param code
 * @param v
 */
VOID
thread_finished(THREADID tid, CONTEXT *ctxt, const INT32 code, VOID *v);

/**
 * Helper (syntax sugar for long code line) to retreive a thread specific data
 * structures.
 * @param tid
 * @return thread specific data structure for the given thread ID
 */
ThreadTrace*
get_tls(THREADID tid);

/**
 * Used for debugging output only.
 * @param tid
 * @param ctxt
 * @param arg
 */
VOID
before_new_fork(THREADID tid, const CONTEXT* ctxt, VOID * arg);

/**
 * Used for debugging output only.
 * @param cp
 * @param arg
 */
BOOL
follow_child_proc(CHILD_PROCESS cp, VOID * arg);

/* BEGIN HELPER */

/**
 * Helper to cast signed integer to string.
 * @param num pointer to the number, which should be casted
 * @return converted string
 */
template <typename T>
string
castsigned2str(const T num);

/**
 * Helper to cast unsigned integer to string.
 * @param num pointer to the number, which should be casted
 * @return converted string
 */
template <typename T>
string
cast2str(const T* num);

/**
 * Helper to cast integer to string.
 * @param num number to be casted
 * @return converted string
 */
template <typename T>
string
cast2str(const T num);

/**
 * Helper (syntax sugar for long code line) to cast operands to truple.
 * @param op_name operand name
 * @param op_value
 * @param op_size
 * @return truple made of params
 */
pair<string, pair<string, uint32_t> >
ops_maker(string op_name, string op_value, uint32_t op_size);

/**
 * Handles a close-syscall and removes the corresponding file descriptor from
 * the socket_fds list.
 * @param fd socket/file descriptor to be closed
 */
VOID
close_fd(ADDRINT fd);
/* END HELPER */

/* BEGIN instruction_trace callbacks */
/**
 * Callback for saving writing register access.
 * @see instruction_trace()
 * @param reg register
 * @param op_size
 * @param tid
 */
VOID PIN_FAST_ANALYSIS_CALL
rec_reg_write(REG reg, UINT32 op_size, THREADID tid);

/**
 * Callback for saving reading register access.
 * @see instruction_trace()
 * @param reg register
 * @param op_size
 * @param tid
 */
VOID PIN_FAST_ANALYSIS_CALL
rec_reg_read(REG reg, UINT32 op_size, THREADID tid);

/**
 * Callback for saving the read memory address.
 * @see instruction_trace()
 * @param addr memory address
 * @param op_size
 * @param tid
 */
VOID PIN_FAST_ANALYSIS_CALL
rec_mem_read(VOID* addr, UINT32 op_size, THREADID tid);

/**
 * Callback for saving the written memory address.
 * @see instruction_trace()
 * @param addr memory address
 * @param op_size
 * @param tid
 */
VOID PIN_FAST_ANALYSIS_CALL
rec_mem_write(VOID* addr, UINT32 op_size, THREADID tid);

/**
 * Callbacks for tracking base register, used to construct a memory address.
 * @see instruction_trace()
 * @param reg register
 * @param tid
 */
VOID PIN_FAST_ANALYSIS_CALL
rec_mem_base(REG reg, THREADID tid);

/**
 * Callbacks for tracking index register, used to construct a memory address.
 * @see instruction_trace()
 * @param reg register
 * @param tid
 */
VOID PIN_FAST_ANALYSIS_CALL
rec_mem_index(REG reg, THREADID tid);

/**
 * Callbacks for adding an immediate operand to the instruction state.
 * Interesting, for, e.g., cmp.
 * @see instruction_trace()
 * @param imm immediate register value
 * @param op_size
 * @param tid
 */
VOID PIN_FAST_ANALYSIS_CALL
rec_imm(UINT64 imm, UINT32 op_size, THREADID tid);

/**
 * Callback for tracking an immediate value, used to construct a memory address.
 * @see instruction_trace()
 * @param imm immediate register value
 * @param op_size
 * @param tid
 */
VOID PIN_FAST_ANALYSIS_CALL
rec_mem_imm(UINT64 imm, UINT32 op_size, THREADID tid);

/**
 * Callback for creation of an instruction state. This is achived by collecting
 * all current CPU register values and including the previously collected
 * operands. Last step of the instruction_trace function.
 * @see instruction_trace()
 * @param ins_addr
 * @param ctxt
 * @param instr
 * @param iclass
 * @param mn_type
 * @param tid
 */
VOID PIN_FAST_ANALYSIS_CALL
create_state(const ADDRINT ins_addr, const UINT32 iclass, CONTEXT* ctxt, string instr, string mn_type,
        THREADID tid);
/* END instruction_trace callbacks */

