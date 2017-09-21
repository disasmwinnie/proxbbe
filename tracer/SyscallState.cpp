#include "SyscallState.h"

SyscallState::SyscallState(const unsigned long long buf_addr,
                const unsigned long long buf_size,
                const std::string ip,
                const int flags,
                const unsigned long long fd)
        : ExecState::ExecState(ip, ExecState::SYSCALL), _buf_addr(buf_addr),
        _buf_size(buf_size), _flags(flags), _fd(fd) {}

SyscallState::SyscallState(const SyscallState &obj)
        : ExecState::ExecState(obj)
{
  _buf_addr = obj._buf_addr;
  _buf_size = obj._buf_size;
  _count = obj._count;
  _b64_message = obj._b64_message; // call copy constructor
  _flags = obj._flags;
  _fd = obj._fd;
}

SyscallState::~SyscallState() {}

void
SyscallState::count(unsigned long long count) { _count = count; }

void
SyscallState::b64_message(const std::string b64_message) { _b64_message = b64_message; }

unsigned long long
SyscallState::buf_addr() { return _buf_addr; }

int
SyscallState::flags() { return _flags; }

unsigned long long
SyscallState::fd() { return _fd; }

std::string
SyscallState::dump_data()
{
  std::ostringstream data;
  data << "{\"type\":" << _st << ",";
  data << "\"ip\":\"" << _ip << "\",";
  data << "\"buf_addr\":" << _buf_addr << ",";
  data << "\"buf_size\":" << _buf_size << ",";
  data << "\"count\":" << _count << ",";
  data << "\"flags\":" << _flags << ",";
  data << "\"msg\":\"" << _b64_message << "\"";
  data << "}";
  return data.str();
}
