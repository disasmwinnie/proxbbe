#include "InsState.h"
#include <iostream>

InsState::InsState(unsigned long long* regs,
    const std::string ip,
    std::list<std::pair<std::string, std::pair<std::string, uint32_t> > >* op_access,
    std::string mn_type,
    uint32_t iclass,
    std::string instr)
    : ExecState::ExecState(ip, ExecState::INS),
    _regs(regs), 
    _op_access(op_access),
    _mn_type(mn_type),
    _iclass(iclass),
    _instr(instr) {}

InsState::~InsState()
{
    delete[] _regs;
    delete _op_access;
}

std::string InsState::dump_data()
{
  std::ostringstream data;
  data << "{\"type\":" << _st << ",";
  data << "\"ip\":\"" << _ip << "\",";
  data << "\"mn_type\":\"" << _mn_type << "\",";
  data << "\"iclass\":" << _iclass << ",";
  data << "\"instruction\":\"" << _instr << "\",";
  data << "\"op_access\":[";

  for(std::list<std::pair<std::string, std::pair<std::string, uint32_t> > >::const_iterator it = _op_access->begin();
      it != _op_access->end();
      ++it)
  {
    // it->first = 'imm'
    // it->second->first = 182283
    // it->second->second = 32
    // "imm":[123,123]
    data << "{\"" << it->first << "\":[";
    if( !it->first.compare("mr") ||
        !it->first.compare("mw") ||
        !it->first.compare("imm") )
    {
      data << it->second.first << ",";
    }
    else
    {
      data << "\"" << it->second.first << "\",";
    }
    data << (it->second.second / 8) << "]";
    /*
     * end() shows NOT to the last element but to the element after that!
     * For whatever reason. Hence the pointer decrement.
     * See http://en.cppreference.com/w/cpp/container/map/rbegin
     */
    if( it != --_op_access->end() )
    {
      data << "},";
    }
    else
    {
      data << "}";
    }
  }
  data << "],";
  data << "\"regs\":{";
  /*
   * We need to hold the IP as a hex string so we can match it later against
   * the opcodes in the assembly. Additionally, we need its value for operands'
   * calculations. Since PIN doesn't support C++11, we cast it the C-style.
   * no need to check whether cast was successfull, since IP is always unsigned.
   */
  data << "\"rip\":" << strtoull(_ip.c_str(), NULL, 16) << ",";
  data << "\"rdi\":" << _regs[0]  << ",";
  data << "\"rsi\":" << _regs[1]  << ",";
  data << "\"rbp\":" << _regs[2]  << ",";
  data << "\"rsp\":" << _regs[3]  << ",";
  data << "\"rbx\":" << _regs[4]  << ",";
  data << "\"rdx\":" << _regs[5]  << ",";
  data << "\"rcx\":" << _regs[6]  << ",";
  data << "\"rax\":" << _regs[7]  << ",";
  data << "\"r8\":"  << _regs[8]  << ",";
  data << "\"r9\":"  << _regs[9]  << ",";
  data << "\"r10\":" << _regs[10] << ",";
  data << "\"r11\":" << _regs[11] << ",";
  data << "\"r12\":" << _regs[12] << ",";
  data << "\"r13\":" << _regs[13] << ",";
  data << "\"r14\":" << _regs[14] << ",";
  data << "\"r15\":" << _regs[15] << ",";
  data << "\"flags\":" << _regs[16] << "}}";

  return data.str();
}
