# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Utils module to help decide whether multiple read-/recv*-syscalls should be
# merged and handled as _one_ network message/packet. This is a module which
# abstracts the desicion away from the "daily" logic, hence the name.
module BufferedReadingOracle
  # Holds constants with possible values for flags parameters, defined in
  # "sys/socket.h", whiche could used in recv* syscalls.

  # close-on-exit flag, must be handled in Tracer. At this point purely
  # informational.
  MSG_CMSG_CLOEXEC =  1073741824
  # Non-blocking. Makes sense to used this with poll or select.
  # Purely informational.
  MSG_DONTWAIT =  64
  # Means there was an error and the buffer contains the packet, that was not
  # sent. If this was previously not set, a new packet must begin. As, when
  # next recv* that has this flag _not_ set must be a new packet.
  MSG_ERRQUEUE =  8192
  # Receive out-of-band data. This call is used (or makes sense to use) when
  # a SIGURG was received. This basically tells, that "urgent" data should be
  # received. If a recv* with this flags arrives, handle it as new packet.
  MSG_OOB =  1
  # The queue for receiving queue is not incremented. Analogus to
  # lseek(fd, 0, SEEK_SET). When this flag is used, handle next recv* as
  # contining message.
  MSG_PEEK =  2
  # Return the real length of datagram, even if it didn't fit into the buffer.
  MSG_TRUNC =  32
  # Explicitly, purely informational.
  MSG_WAITALL =  256

  def cmsg_cloexec_set?(flags)
    return flags & MSG_CMSG_CLOEXEC == MSG_CMSG_CLOEXEC ? true : false
  end

  def dontwait_set?(flags)
    return flags & MSG_DONTWAIT == MSG_DONTWAIT ? true : false
  end

  def errqueue_set?(flags)
    return flags & MSG_ERRQUEUE == MSG_ERRQUEUE ? true : false
  end

  def oob_set?(flags)
    return flags & MSG_OOB == MSG_OOB ? true : false
  end

  def peek_set?(flags)
    return flags & MSG_PEEK == MSG_PEEK ? true : false
  end

  def trunc_set?(flags)
    return flags & MSG_TRUNC == MSG_TRUNC ? true : false
  end

  def waitall_set?(flags)
    return flags & MSG_WAITALL == MSG_WAITALL ? true : false
  end

  # Constants to determine whether multiple recv*-calls belong to the same
  # network message.
  module ACTION
    # It's a continuous packet, go on and handle this as one packet.
    CONTINUE = 1000
    # This is a new packet.
    CREATE_NEW = 1001
    # Don't use THIS packet at all since
    SKIP = 1002
    PEEK = 1003       # See flag description above.
  end

  # Checks whether buffered reading is in progress. In positive case, the
  # consequence should be that more packets are added to one message.
  # @param flags [Integer] parameter of recv*-syscall
  # @param buf_size [Integer] size of buffer that holds data from network
  # @param byte_count [Integer] amount of data received at the socket
  # @return [ACTION] returns an action to state what to do with it.
  def what_action_to_take(flags, buf_size, byte_count)
    log_msg(flags)
    action = nil
    # This is the case when this is the first packet in the whole trace.
    if (@last_packet_flags.nil? || @last_packet_buf_size.nil? ||
        @last_packet_buf_size.nil?)
      action = ACTION::CONTINUE # Continue, since it's the first packet anyway.
    elsif @last_packet_byte_count == 0
      action = ACTION::CREATE_NEW # Last packet was not usable, create new.
    elsif byte_count == 0
      action = ACTION::SKIP # This packet, is empty or faulty, don't use it.
    elsif peek_set?(flags)
      action = ACTION::PEEK
    elsif errqueue_set?(flags)
      $log.warn("Received data with buf_size: #{buf_size} and count: " +
                "#{byte_count}, had the MSG_ERRQUEUE flag set")
      action = ACTION::CREATE_NEW
    elsif oob_set?(flags)
      action = ACTION::CREATE_NEW
    elsif trunc_set?(flags) &&
      @last_packet_buf_size > @last_packet_byte_count
      $log.warn("Received data with buf_size: #{buf_size} smaller then count:" +
                " #{byte_count}, had the MSG_TRUNC flag set. Check manually " +
                "if the next packet belongs to this one!!! Can't decide it " +
                "for myself. Sorry, yours ProXBBE.")
      action = ACTION::CREATE_NEW
    elsif @last_packet_buf_size >= @last_packet_byte_count &&
        #@last_packet_flags == flags
      # This case also catches all possible flags bellow, if they receive
      # further data through multiple syscalls.
      action = ACTION::CREATE_NEW # Buffer not filled, last packet was complete.
    end
    if action.nil?
      $log.warn("Don't know which action to take due flags. Create a new " +
                "network message. MSG: buf_size: #{buf_size}, byte_count: " +
                "#{byte_count}, flags: #{flags}. Previous message was: " +
                "buf_size: #{@last_packet_buf_size}, byte_count: " +
                "#{@last_packet_byte_count}, flags: #{@last_packet_flags}.")
      action = ACTION::CREATE_NEW
    end
    @last_packet_flags = flags
    @last_packet_buf_size = buf_size
    @last_packet_byte_count = buf_size
    return action
  end

  private
  # @!visibility private
  # Helper to which evaluates the flags and prints an informational message
  # if it makes sense.
  def log_msg(flags)
    if cmsg_cloexec_set?(flags)
      $log.info("MSG_CMSG_CLOEXEC flag set in recv*-syscall. No action needed.")
    elsif dontwait_set?(flags)
      $log.info("MSG_DONTWAIT flag set in recv*-syscall. No action needed.")
    elsif errqueue_set?(flags)
      $log.info("MSG_ERRQUEUE flag set in recv*-syscall. No action needed.")
      $log.info("Means there was an error and the buffer contains the " +
                "packet, that was not sent. If this was previously not set, " +
                "a new packet must begin. As, when next recv* that has this " +
                "flag _not_ set must be a new packet.")
    elsif oob_set?(flags)
      $log.info("MSG_OOB flag set in recv*-syscall. No action needed.")
      $log.info("Receive out-of-band data. This call is used (or makes sense" +
                " to use) when a SIGURG was received. This basically tells, " +
                "that urgent data should be received. If a recv* with this " +
                "flags arrives, handle it as new packet.")
    elsif peek_set?(flags)
      $log.info("MSG_PEEK flag set in recv*-syscall.")
      $log.info("The queue for receiving queue is not incremented. Analogus " +
                "to lseek(fd, 0, SEEK_SET). When this flag is used, handle " +
                " next recv* as contining message.")
    elsif trunc_set?(flags)
      $log.info("MSG_TRUNC flag set in recv*-syscall.")
      $log.info("Return the real length of datagram, even if it didn't fit " +
                "into the buffer.")
    elsif waitall_set?(flags)
      $log.info("MSG_WAITALL flag set in recv*-syscall. No action needed.")
    end
  end
end
