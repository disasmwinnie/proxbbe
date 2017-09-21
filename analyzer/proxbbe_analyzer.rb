#!/usr/bin/env ruby
# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)

require 'time'
require 'json'
require 'logger'
# Set global log level.
LOG_LEVEL = Logger::DEBUG

# String converter for mixed printable and non-printable character strings.
def convstr(str)
  return '' if str.nil?
  new_str = ''
  str.each_byte do |b|
    if (b < 128 && b > 31) || b == 10 || b == 13 # \r\n
      new_str << b.chr
    else
    new_str << sprintf("\\x%02x", b)
    end
  end
  return new_str
end

# Usage information. Called in cased ProXBBE parameters used wrongly. Exists
# program with error.
def usage
  STDERR.puts('Either argument missing or the .jsonl file can not accessed.')
  STDERR.puts("Usage: #{$0} [--no-buf-read] trace_output.jsonl")
  exit(1)
end

# Checks whether argumets given and extracts. Additionally checking for correct
# file name and whether it's readable.
# @return [Array] first element contains trace file, second is buffered reading
# off-/on-switch
def process_args
  usage if ARGV.empty?

  ret = [nil, true]

  if ARGV.length == 2
    if ARGV[0].include?('--no-buf-read')
      ret[1] = false
      ret[0] = ARGV[1]
    elsif ARGV[1].include?('--no-buf-read')
      ret[1] = false
      ret[0] = ARGV[0]
    end # else, stays nil
  elsif ARGV.length == 1
    ret[0] = ARGV[0]
  end # else, stays nil

  # Also check for pipes in file names to prevent exec() beeing called.s
  # See popen-doc for reason.
  usage if ret[0].nil? || !File.readable?(ret[0]) ||
    !ret[0].end_with?('.jsonl') || ret[0].include?('|')

  return ret
end

# Parses the jsonl file, gives informational notices, initializes different
# engines used during the analysis. Loops through the trace and analyzes it
# by utilizeing the mentioned engines.
def main()
  args = process_args
  jsonl_file = args[0]
  do_buf_read = args[1]
  b_file = File.basename(jsonl_file, '.jsonl')
  log_file = File.open(b_file + '.log',  File::WRONLY | File::CREAT)
  out_file_name = b_file + '.proxbbe'
  # log into the current folder.
  $log = Logger.new(log_file, level: LOG_LEVEL)

  buf_info_msg = nil
  if do_buf_read
    buf_info_msg = 'Will try to detect buffered reading. If you want ProXBBE ' +
      'to see the whole trace as one packet use "--no-buf-read" argument.'
  else
    buf_info_msg = 'Buffered reading detection is off. Interpreting the ' +
      'trace as one packet.'
  end
  $log.info(buf_info_msg)
  STDERR.puts(buf_info_msg)

  $log.info("Processing #{b_file}.jsonl")
  STDERR.puts("Processing #{b_file}.jsonl")
  require_relative 'utils/loading_spinner'
  progress_bar = LoadingSpinner.new
  progress_bar.start
  anal_started = Time.now # Track time

  inferred_msgs = []
  require_relative 'inference_engine/message'
  im = nil
  require_relative 'utils/buffered_reading_oracle'
  include BufferedReadingOracle
  include BufferedReadingOracle::ACTION

  require_relative 'utils/instruction_state'
  msg_peek_found = false
  IO.foreach(jsonl_file) do |line|
    state = JSON.parse(line)
    if state['type'] == 0 # Instruction state
	  is = InstructionState.new(state)
      im.analyze_state(is)
	  is = nil
    else                  # Syscall state
      if do_buf_read
        data_action = BufferedReadingOracle::what_action_to_take(state['flags'],
                                  state['buf_size'],
                                  state['count'])
        if data_action == ACTION::PEEK
          msg_peek_found = true
        end
        if msg_peek_found
          if data_action == ACTION::PEEK # first MSG_PEEK packet
            inferred_msgs << im
            im = Message.new
          end
          im.add_syscall(state['buf_addr'], state['buf_size'], state['count'],
                         state['msg'], action=ACTION::PEEK)
          if data_action != ACTION::PEEK
            msg_peek_found = false
          end
        elsif data_action == ACTION::CONTINUE
          im = Message.new if im.nil? # Take care of very first packet.
          im.add_syscall(state['buf_addr'], state['buf_size'], state['count'],
                         state['msg'], action=data_action)
        elsif data_action == ACTION::CREATE_NEW
          inferred_msgs << im
          im = Message.new
          im.add_syscall(state['buf_addr'], state['buf_size'], state['count'],
                         state['msg'], action=data_action)
        end
      else
        if im && im.packets.count > 0 # Take care of very first packet.
          inferred_msgs << im
        end
        im = Message.new
        im.add_syscall(state['buf_addr'], state['buf_size'], state['count'],
                       state['msg'])
      end
    end
  end
  inferred_msgs << im
  progress_bar.stop
  $log.info("Tainting and preprocessing finished. Starting Analysis.")
  STDERR.puts("Tainting and preprocessing finished. Starting Analysis.")
  progress_bar = LoadingSpinner.new
  progress_bar.start
  out_file = File.open(out_file_name, 'w')
  inferred_msgs.each do |i_msg|
    out_file.write("Inferred model of packet: \n\n")
    out_file.write(i_msg.infer_msg)
    out_file.write("\n")
  end
  progress_bar.stop
  $log.info("Done. Result is written into #{out_file_name}.")
  span_for_anal = Time.at(Time.now - anal_started).gmtime.strftime("%H:%M:%S")
  STDERR.puts("Done in #{span_for_anal}. Result is written into #{out_file_name}.")
  out_file.close
end

if __FILE__ == $0
  main()
end

