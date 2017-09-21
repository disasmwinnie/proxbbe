#ifndef InsState_H_
#define InsState_H_

#include "ExecState.h"
#include <sstream>
#include <string>
#include <list>
/**
 * @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
 *
 * @class InsState
 *
 * A special execution state which contains an assembly
 * instruction, accompanied by operands and CPU state.
 * @see ExecState
 */
class
InsState : public ExecState
{
  /*
    rdi, rsi, rbp, rsp, rbx, rdx, rcx, rax, r8, r9, r10, r11, r12, r13, r14, r15
  */
  unsigned long long* _regs; /**< Containing all CPU GPRs and FLAGs. */
  std::list<std::pair<std::string, std::pair<std::string, uint32_t> > >*
    _op_access; /**< Contains operands of the instruction and information about
                  how they are accessed (size) */
  std::string _mn_type; /**< Mnemonic type, (PINs representation). */
  uint32_t _iclass; /**< Instruction class, (PINs representation). */
  std::string _instr; /**< The whole instruction as a string (for dbg purposes). */
 public:
  /**
   * Initializes all instance variables which represent an instructin state.
   * @param regs contains all CPU GPRs and FLAGs
   * @param ip instruction pointer / program counter
   * @param op_access contains operands of the instruction and information about
   *              how they are accessed (size)
   * @param mn_type mnemonic type: PINs representation
   * @param instr the whol instruction in string representation
   */
  InsState(unsigned long long* regs,
      const std::string ip,
      std::list<std::pair<std::string, std::pair<std::string, uint32_t> > >* op_access,
      std::string mn_type,
      uint32_t iclass,
      std::string instr);

  /**
   * Desctructor.
   */
  ~InsState();

  std::string dump_data();
};
#endif
