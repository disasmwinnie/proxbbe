#ifndef SyscallState_H_
#define SyscallState_H_

#include "ExecState.h"
#include <string>
#include <sstream>

/**
 * @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
 *
 * @class SyscallState

 * A special execution state which contains information of a
 * syscall responsible for receiving network packets. This information includes
 * the buffer address, the buffer size and how many bytes were actually written
 * into the buffer.
 * @see ExecState
 */
class
SyscallState : public ExecState
{
  unsigned long long _buf_addr; /**< buffer address of network packet */
  unsigned long long _buf_size; /**< buffer size */
  unsigned long long _count; /**< The count actually could be -1 in case of
                               error. In this case an overflow happens and
                               _count has an incredibly high number which can be
                               used during analysis to skip the syscall. */
  std::string _b64_message; /**< Network message received by syscall. */
  int _flags;  /**< Flags used for recv* syscalls. Can be zero. In case of
                 read syscall always zero. */
  unsigned long long _fd; /**< File/socket descriptor. Not printed to trace
                            but used in case of MSG_CMSG_CLOEXEC flag. */
 public:
  /**
   * Initializes all instance variables that represent an instruction trace.
   * @param buf_addr buffer address of network packet
   * @param buf_size buffer size
   * @param ip instruction pointer / program counter
   * @param flags of recv* syscalls, is zero for read
   */
  SyscallState(const unsigned long long buf_addr,
                  const unsigned long long buf_size,
                  const std::string ip,
                  const int flags,
                  const unsigned long long fd);
  /**
   * Copy constructor
   * @param obj pointer to object to be cloned
   */
  SyscallState(const SyscallState &obj);

  ~SyscallState();
  /**
   * Setter for the amount of written bytes during the syscall.
   * @param count amount of written bytes
   */
  void
  count(unsigned long long count);

  /**
   * Setter for network message.
   * @param b64_message network packet contend as base64 string
   */
  void
  b64_message(const std::string b64_message);

  /**
   * Getter for the buffer address.
   * @return memory address of the message
   */
  unsigned long long
  buf_addr();

  /**
   * Getter for flags parameter of recv*-syscall.
   * @return flags variable
   */
  int
  flags();

  /**
   * Getter for file/socket descriptor.
   * @return file/socket descriptor.
   */
  unsigned long long
  fd();

  /**
   * Creates a string with jsonl entry for a Syscall State.
   * @return SyscallState as jsonl string.
   */
  std::string dump_data();
};
#endif
