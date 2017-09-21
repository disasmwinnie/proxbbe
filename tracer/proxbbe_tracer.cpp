#include "proxbbe_tracer.h"

int
main(INT32 argc, CHAR** argv)
{

	// init lock
	PIN_InitLock(&lock);

  // Get a key for ThreadLocalStorage (TLS).
  tls_key = PIN_CreateThreadDataKey(NULL);

	// Initialize pin
	if (PIN_Init(argc, argv)) return usage();

  // Add callback for syscalls
	PIN_AddSyscallEntryFunction(syscall_handler_before, NULL);
	PIN_AddSyscallExitFunction(syscall_handler_after, NULL);

  //Register ThreadStart to be called when a thread starts.
  PIN_AddThreadStartFunction(thread_started, NULL);

  PIN_AddForkFunction(FPOINT_BEFORE, before_new_fork, NULL);

  PIN_AddFollowChildProcessFunction(follow_child_proc, NULL);

	// Add PIN exit function
	PIN_AddFiniFunction(p_finished, NULL);

  string cmd_fds = KnobFileDescriptors.Value();
  if( cmd_fds.compare("") != 0 )
  {
    LOG("Socket/file descriptors from cmd: " + cmd_fds + "\n");
    list<string> fds = split_fds(cmd_fds);
    for (list<string>::iterator it = fds.begin();
            it != fds.end(); ++it)
    {
      string tmp = *it;
      UINT32 fd = strtol(tmp.c_str(), NULL, 10);
      socket_fds.push_back(fd);
    }
  }

  PIN_StartProgram();

  return EXIT_SUCCESS;
}

list<string>
split_fds(string fds)
{
  list<string> elements;
  string::size_type c_pos = 0;
  string::size_type token_pos = fds.find(',');
  while(token_pos != string::npos)
  {
    elements.push_back(fds.substr(c_pos, token_pos));
    c_pos = token_pos + 1;
    token_pos = fds.find(',', c_pos);
  }
  // last file descriptor
  elements.push_back(fds.substr(c_pos, fds.length()));
  return elements;
}

VOID
handle_recvmsg(void *msghdr_ptr, ADDRINT* buf_addr, ADDRINT* buf_size)
{
  struct msghdr m = {0};
  PIN_SafeCopy(&m, msghdr_ptr, sizeof(m));
  if(m.msg_iovlen > 1) LOG(recvmsg_iovec);
  assert(m.msg_iovlen > 0);
  struct iovec i = {0};
  PIN_SafeCopy(&i, m.msg_iov, sizeof(i));
  *buf_addr = (ADDRINT)i.iov_base;
  *buf_size = i.iov_len;
  DBG("msghdr iov_len: " + decstr(m.msg_iovlen) + ", buf_addr: "
          + decstr(*buf_addr) + ", buf_size: " + decstr(*buf_size) + "\n");
}

VOID
DBG(string msg)
{
  if( debug_mode ) LOG("_[DBG]_ " + msg);
}

INT32
usage()
{
	PIN_ERROR("Printing syscalls for network recv.\n"
			+ KNOB_BASE::StringKnobSummary() + "\n");
	return EXIT_FAILURE;
}

VOID
p_finished(const INT32 code, VOID* v)
{
  LOG("TARGET TOOL FINISHED, pintool writing output trace.\n");
  string pin_pid = decstr(PIN_GetPid());
  for( list<UINT32>::iterator it = running_threads.begin();
          it != running_threads.end(); ++it )
  {
    UINT32 tid = *it;
    LOG("PROXBBE PIN-TRACER: saving trace for pid:  " + pin_pid
            + ", threadid: " + decstr(tid) + "\n");

    string f_name =   KnobOutputFile.Value() + "-pid" + pin_pid
                + "-tid" + decstr(tid)+ ".jsonl";
	  trace.open(f_name.c_str());
    LOG("Opened file: " + f_name + " and starting trace dump.\n");
    ThreadTrace* t_trace = get_tls(tid);
    list<ExecState*> et = t_trace->exec_states;

    for( list<ExecState*>::iterator es_it = et.begin();
            es_it != et.end(); ++es_it )
    {
      ExecState *exec_state = *es_it;
      trace << exec_state->dump_data() << endl;
    }

	  trace.flush();
	  trace.close();
    delete t_trace;
    LOG("Closed file: " + f_name + " and finished trace dump.\n");
  }
  LOG("--- PROXBBE PIN-TRACER: finished.  ---\n");
}

VOID
syscall_handler_before(THREADID tid, CONTEXT* ctxt,
		SYSCALL_STANDARD sctd, VOID* v)
{
  /**
   * Used to extract the cmd line arguments of functions that can receive
   * network messages. It checks for certain syscalls which are or could be
   * responsible for the explained function. If they use a file descriptor
   * associated with a socket then the arguments are extracted.
   */
  ADDRINT sys_nr = PIN_GetSyscallNumber(ctxt, sctd);
  ADDRINT fd = PIN_GetSyscallArgument(ctxt, sctd, 0);
  ADDRINT buf_addr;
  ADDRINT buf_size;
  INT32 flags = 0;

  PIN_GetLock(&lock, tid+1);
  // Make sure the socket call is for Internet connection only. Eleminates
  // some noise.
  if( sys_nr == SOCKET_SYSCALL && (fd == AF_INET || fd == AF_INET6) )
  {
    socket_called = true;
    PIN_ReleaseLock(&lock);
    DBG("socket()-syscall happend.\n");
    return;
  } else if( sys_nr == CLOSE_SYSCALL )
  {
    close_fd(fd);
    PIN_ReleaseLock(&lock);
    return;
  } else if( sys_nr == SOCKETPAIR_SYSCALL || sys_nr == PIPE_SYSCALL
          || sys_nr == PIPE2_SYSCALL )
  {
    LOG(socketpair_msg);
    PIN_ReleaseLock(&lock);
    return;
  } else if( sys_nr == RECVMSG_SYSCALL
          || sys_nr == RECVFROM_SYSCALL
          || sys_nr == READ_SYSCALL )
  {
    // negative if the given fd is not a socket fd.
    list<ADDRINT>::const_iterator it = find(socket_fds.begin(),
            socket_fds.end(), fd);
    if( it == socket_fds.end() )
    {
      if( sys_nr == READ_SYSCALL )
      {
        PIN_ReleaseLock(&lock);
        return;
      } else
      {
        LOG("--recv*() syscall, but no active socket/file descriptor. This \
me  ans socket() was skipped. Probably socket()-call was made \
be  fore fork() and this is its child with inherited fd.\n");
      }
    }
    if ( sys_nr == RECVMSG_SYSCALL )
    {
      DBG("Received packet via recvmsg() syscall.");
      handle_recvmsg((void*)PIN_GetSyscallArgument(ctxt, sctd, 1),
              &buf_addr, &buf_size);
      flags = PIN_GetSyscallArgument(ctxt, sctd, 2); // third arg for recvmsg
    } else
    {
      DBG("Received packet via recvfrom() or open() syscall.");
		  buf_addr = PIN_GetSyscallArgument(ctxt, sctd, 1);
		  buf_size = PIN_GetSyscallArgument(ctxt, sctd, 2);
      // read() has no flags arg, the other do as fourth arg.
      if( sys_nr != READ_SYSCALL ) flags = PIN_GetSyscallArgument(ctxt, sctd, 3);
    }
    LOG("Packet received.\n");
  } else
  {
    PIN_ReleaseLock(&lock);
    return;
  }
  PIN_ReleaseLock(&lock);
	ADDRINT ip = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);

  stringstream tmp;
  tmp << hex << ip;

  ThreadTrace* t_trace = get_tls(tid);
	t_trace->tmp_syscall_state = new SyscallState(buf_addr, buf_size, tmp.str(),
          flags, fd);

  // Start recodring execution.
  PIN_GetLock(&lock, tid+1);
  rec_in_progress = true;
  if(!trace_running)
  {
    TRACE_AddInstrumentFunction(instruction_trace, NULL);
    trace_running = true;
  }
  PIN_ReleaseLock(&lock);
}

VOID
syscall_handler_after(THREADID tid, CONTEXT* ctxt,
		SYSCALL_STANDARD sctd, VOID* v)
{
  if( rec_in_progress )
  {
    PIN_GetLock(&lock, tid+1);
    rec_in_progress = false;
    PIN_ReleaseLock(&lock);
    ThreadTrace* t_trace = get_tls(tid);
    assert(t_trace->tmp_syscall_state != NULL);
    SyscallState* syscall_state = t_trace->tmp_syscall_state;
    ADDRINT ret = PIN_GetSyscallReturn(ctxt, sctd);
    /* Copy the network message content into the syscall state and set length
     * of the actual length of the packet (not the buffer lenght).
     *
     * ATTENTION: If ret is -1, then ADDRINT overflows. According to the manpage
     * of recv*() and open() syscalls the return value can only be -1, positive,
     * or 0.
     */
    if( ret == ((ADDRINT)-1) || ret == 0 )
    {
      LOG("WARN: size of received bytes 0 or negative. Nothing received or recv*/open failed.");
      syscall_state->b64_message("");
      syscall_state->count(0);
    } else if( ret > 0 )
    {
      unsigned char buf[ret];
      memset(buf, 0, ret);
      DBG("Packet copied from " + decstr((INT64) syscall_state->buf_addr()) +
              ", ret: " + decstr( ret ) + "\n");
      PIN_SafeCopy( buf, (VOID*) syscall_state->buf_addr(), ret );
      syscall_state->b64_message( base64_encode(buf, ret) );
      syscall_state->count(ret);
    }
    /* Handle MSG_CMSG_CLOEXEC flag, which closes socket automatically. */
    if ( (syscall_state->flags() & 1073741824) == 1073741824 )
    {
      PIN_GetLock(&lock, tid+1);
      close_fd(syscall_state->fd());
      LOG("Closed file descriptor due MSG_CMSG_CLOEXEC flag\n");
      PIN_ReleaseLock(&lock);
    }
    for( list<UINT32>::iterator it = running_threads.begin();
              it != running_threads.end(); ++it )
    {
      UINT32 r_tid = *it;
      ThreadTrace* t_trace = get_tls(r_tid);
      // Spare an obj copy.
      if(it != running_threads.begin())
        syscall_state = new SyscallState(*syscall_state);

      // Locking, since other threads could be accessing their own resources.
      PIN_GetLock(&lock, r_tid+1);
      t_trace->exec_states.push_back(syscall_state);
      PIN_ReleaseLock(&lock);
    }
  }
  if( socket_called )
  {
    UINT32 ret = PIN_GetSyscallReturn(ctxt, sctd);
    PIN_GetLock(&lock, tid+1);
    socket_fds.push_back(ret);
    socket_called = false;
    PIN_ReleaseLock(&lock);
    DBG("socket() return value (fd): " + decstr(ret) + "\n");
  }
}

VOID
instruction_trace(const TRACE trace, VOID* v)
{
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {

    // Get amount of memory operands and iterate through them.
    UINT32 mem_count = INS_MemoryOperandCount(ins);

    for(UINT32 mem_op = 0; mem_op < mem_count; ++mem_op)
    {
      UINT32 op_size = INS_OperandWidth(ins, mem_op);
      if( INS_MemoryOperandIsRead(ins, mem_op) )
      {
        INS_InsertCall(ins,
            IPOINT_BEFORE,
            (AFUNPTR)rec_mem_read,
            IARG_MEMORYOP_EA, mem_op,
            IARG_UINT32, op_size,
            IARG_THREAD_ID,
            IARG_END);
      }
      if( INS_MemoryOperandIsWritten(ins, mem_op) )
      {
        INS_InsertCall(ins,
            IPOINT_BEFORE,
            (AFUNPTR)rec_mem_write,
            IARG_MEMORYOP_EA, mem_op,
            IARG_UINT32, op_size,
            IARG_THREAD_ID,
            IARG_END);
      }
      REG base = INS_MemoryBaseReg(ins);
      REG index = INS_MemoryIndexReg(ins);
      if( REG_valid(base) )
      {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rec_mem_base,
            IARG_UINT32, base,
            IARG_THREAD_ID,
            IARG_END);
      }
      if( REG_valid(index) )
      {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rec_mem_index,
            IARG_UINT32, index,
            IARG_THREAD_ID,
            IARG_END);
      }
    }

    UINT32 op_count = INS_OperandCount(ins);
    for(UINT32 op = 0; op < op_count; ++op)
    {
      UINT32 op_size = INS_OperandWidth(ins, op);
      if( INS_OperandIsReg(ins, op) )
      {
        if( INS_OperandRead(ins, op) )
        {
          INS_InsertCall(ins,
              IPOINT_BEFORE,
              (AFUNPTR)rec_reg_read,
              IARG_UINT32, INS_OperandReg(ins, op),
              IARG_UINT32, op_size,
              IARG_THREAD_ID,
              IARG_END);
        }
        if( INS_OperandWritten(ins, op) )
        {
          INS_InsertCall(ins,
              IPOINT_BEFORE,
              (AFUNPTR)rec_reg_write,
              IARG_UINT32, INS_OperandReg(ins, op),
              IARG_UINT32, op_size,
              IARG_THREAD_ID,
              IARG_END);
        }
      }
      if( INS_OperandIsImmediate(ins, op) )
      {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rec_imm,
            IARG_UINT64, INS_OperandImmediate(ins, op),
            IARG_UINT32, op_size,
            IARG_THREAD_ID,
            IARG_END);
      }
    }

    // LEA not considered as memory operand. But it still could have index/base
    // registers.
    if( INS_IsLea(ins) )
    {
      // base, index... are valid not only for memory ops but also for LEA.
      REG base = INS_MemoryBaseReg(ins);
      REG index = INS_MemoryIndexReg(ins);
      if( REG_valid(base) )
      {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rec_mem_base,
            IARG_UINT32, base,
            IARG_THREAD_ID,
            IARG_END);
      }
      if( REG_valid(index) )
      {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rec_mem_base,
                IARG_UINT32, index,
                IARG_THREAD_ID,
                IARG_END);
      }
    }

    INS_InsertCall(ins,
        IPOINT_BEFORE,
        (AFUNPTR)create_state,
        IARG_INST_PTR,
        IARG_UINT32, INS_Opcode(ins),
        IARG_CONST_CONTEXT,
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_PTR, new string(CATEGORY_StringShort(INS_Category(ins))),
        IARG_THREAD_ID,
        IARG_END);

    }
  }
}

VOID
thread_started(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
  /* We don't check here whether trace instrumentation is running, we assume
   * it will be at some point (very soon).
   * */
  DBG("Thread-Start with tid: " + decstr(tid) + "\n");
  ThreadTrace* t_trace = new ThreadTrace;
  t_trace->ops = new list<pair<string, pair<string, uint32_t> > >();
  PIN_SetThreadData(tls_key, t_trace, tid);
  PIN_GetLock(&lock, tid+1);
  running_threads.push_back(tid);
  PIN_ReleaseLock(&lock);
}

VOID
thread_finished(THREADID tid, CONTEXT *ctxt, const INT32 code, VOID *v)
{
  DBG("Thread-Finish with tid: " + decstr(tid) + "\n");
  PIN_GetLock(&lock, tid+1);
  running_threads.remove(tid);
  PIN_ReleaseLock(&lock);
}

ThreadTrace*
get_tls(THREADID tid)
{
  return static_cast<ThreadTrace*>(PIN_GetThreadData(tls_key, tid));
}

VOID
before_new_fork(THREADID tid, const CONTEXT* ctxt, VOID * arg)
{
  DBG("FORK - TID: " + decstr(tid) + " PID: " + decstr(PIN_GetPid()) + "\n");
}

// Callback executed a new child starts.
BOOL
follow_child_proc(CHILD_PROCESS cp, VOID * arg)
{
  DBG("FOLLOW_CHILD - getpid(): " + decstr(getpid()) + " PIN_GetPid(): " + decstr(PIN_GetPid()) + "\n");
  return true;
}

template <typename T>
string
castsigned2str(const T num)
{
  stringstream s;
  int64_t tmp_num;
  tmp_num = (int64_t) num;
  s << tmp_num;
  return s.str();
}

template <typename T>
string
cast2str(const T* num)
{
  stringstream s;
  uint64_t tmp_num;
  tmp_num = (uint64_t) num;
  s << tmp_num;
  return s.str();
}

template <typename T>
string
cast2str(const T num)
{
  stringstream s;
  uint64_t tmp_num;
  tmp_num = (uint64_t) num;
  s << tmp_num;
  return s.str();
}

pair<string, pair<string, uint32_t> >
ops_maker(string op_name, string op_value, uint32_t op_size)
{
  return pair<string, pair<string, uint32_t> >(op_name,
      pair<string, uint32_t>(op_value, op_size));
}

VOID
close_fd(ADDRINT fd)
{
  list<ADDRINT>::iterator it = find(socket_fds.begin(),
          socket_fds.end(), fd);
  if( it != socket_fds.end() )
  {
    socket_fds.erase(it);
    DBG("Closed socket fd: " + decstr(*it) + "\n");
  }
}

VOID PIN_FAST_ANALYSIS_CALL
rec_reg_write(REG reg, UINT32 op_size, THREADID tid)
{
  ThreadTrace* t_trace = get_tls(tid);
  t_trace->ops->push_back( ops_maker("rw", REG_StringShort(reg), op_size) );
}


VOID PIN_FAST_ANALYSIS_CALL
rec_reg_read(REG reg, UINT32 op_size, THREADID tid)
{
  ThreadTrace* t_trace = get_tls(tid);
  t_trace->ops->push_back( ops_maker("rr", REG_StringShort(reg), op_size) );
}

VOID PIN_FAST_ANALYSIS_CALL
rec_mem_read(VOID* addr, UINT32 op_size, THREADID tid)
{
  ThreadTrace* t_trace = get_tls(tid);
  t_trace->ops->push_back( ops_maker("mr", cast2str(addr), op_size) );
}

VOID PIN_FAST_ANALYSIS_CALL
rec_mem_write(VOID* addr, UINT32 op_size, THREADID tid)
{
  ThreadTrace* t_trace = get_tls(tid);
  t_trace->ops->push_back( ops_maker("mw", cast2str(addr), op_size) );
}

VOID PIN_FAST_ANALYSIS_CALL
rec_mem_base(REG reg, THREADID tid)
{
  ThreadTrace* t_trace = get_tls(tid);
  t_trace->ops->push_back( ops_maker("m_base", REG_StringShort(reg), 0) );
}

VOID PIN_FAST_ANALYSIS_CALL
rec_mem_index(REG reg, THREADID tid)
{
  ThreadTrace* t_trace = get_tls(tid);
  t_trace->ops->push_back( ops_maker("m_index", REG_StringShort(reg), 0) );
}

VOID PIN_FAST_ANALYSIS_CALL
rec_imm(UINT64 imm, UINT32 op_size, THREADID tid)
{
  ThreadTrace* t_trace = get_tls(tid);
  t_trace->ops->push_back( ops_maker("imm", cast2str(imm), op_size) );
}

VOID PIN_FAST_ANALYSIS_CALL
create_state(const ADDRINT ins_addr, const UINT32 iclass, CONTEXT* ctxt, string instr, string mn_type,
        THREADID tid)
{
  stringstream tmp;
  // There are 16 GPL registers in x86_64  + 1 of r-/eflags
  unsigned int reg_count = ((unsigned int) REG_GR_LAST) - ((unsigned int) REG_GR_BASE) + 1 + 1;
  unsigned long long* regs = new unsigned long long[reg_count];
  for (int reg = (int)REG_GR_BASE; reg <= (int)REG_GR_LAST; ++reg)
  {
    ADDRINT *val = new ADDRINT;
    PIN_GetContextRegval(ctxt, (REG)reg, reinterpret_cast<UINT8*>(val));
		tmp << hex << *val;
    tmp >> regs[reg - (unsigned int) REG_GR_BASE];
	  // reset stringstream
		tmp.str("");
		tmp.clear();
  }
  // Get flags register
  ADDRINT *val = new ADDRINT;
  PIN_GetContextRegval(ctxt, REG_EFLAGS, reinterpret_cast<UINT8*>(val));
  tmp << hex << *val;
  tmp >> regs[reg_count-1];
	tmp.str("");
	tmp.clear();

  tmp << hex << ins_addr;
  ThreadTrace* t_trace = get_tls(tid);
  InsState* ins_state = new InsState(regs, tmp.str(), t_trace->ops, mn_type,
          iclass, instr);

  t_trace->exec_states.push_back(ins_state);
  t_trace->ops = new list<pair<string, pair<string, uint32_t> > >();
}

