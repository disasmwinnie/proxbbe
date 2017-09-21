#ifndef ExecState_H_
#define ExecState_H_

#include <string>

/**
 * @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
 * @class ExecState
 *
 * Abstract class to describe a "state". A ProXBBE state or "ExecState" is
 * either an executed instruction, along with the corresponding
 * CPU state, or syscall responsible of receiving network packets
 * @see SyscallState
 * @see InsState
 */
class
ExecState
{
 protected:
   std::string _ip; /**< instruction pointer */
  /**
   * Decripbes which state type this object represents.
   */
   enum _state_type
   {
     INS, /**< instruction. */
     SYSCALL /**< systemcall for network packets. */
   } _st; /**< Instance variable of thep _state_type. */

 public:
  /**
   * Initializes instruction pointer and state type.
   * @param ip instruction pointer from trace
   * @param st state type of the ExecType
   */
  ExecState(const std::string ip, const enum _state_type st);
  /**
   * Destructs all dynamic structures of the object.
   */
  virtual ~ExecState();
  /**
   * Dumps the state in form as a JSONL (line).
   * @return a JSON HASH/Key-value containint the state information
   */
  virtual std::string dump_data();
};
#endif
