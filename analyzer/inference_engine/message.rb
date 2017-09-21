# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Represents an inferred message. Which we understand as a subset of received
# network packets, stored along different buffers.
# Main purpose of the class is to have meaningful format to prepare the results
# for output in an arranged way, e.g., to print all fields along with their
# data.
require 'base64'
require_relative '../taint_engine/taint_engine'
require_relative 'fields/delimited_field_inference'
require_relative 'fields/keyword_field_inference'
require_relative 'fields/direction_field_inference'
require_relative 'fields/direction_field_counter_inference'
require_relative 'fields/fixlen_field_inference'
require_relative 'protocol_model'

class Message
  attr_reader :packets, :delimiters, :keywords, :directions_targets, :fixed_length

  def initialize
    @te = TaintEngine.new
    @dir_field = DirectionFieldInference.new
    @dir_count_field = DirectionFieldCounterInference.new
    @del_field = DelimitedFieldInference.new
    @keyword_field = KeywordFieldInference.new
    @fixlen_field = FixlenFieldInference.new
    # Packets, the messages stored in a memory buffer. Every item has the
    # following format:
    # { buf_addr: 0, buf_size: 0, count: 0, msg: "" }
    @packets = []
    # Delimited fields and delimiters.
    @delimiters = []
    # Keyword fileds.
    @keywords = []
    # Direction fields, and the corresponding target fields.
    @directions_targets = nil
    # Fixed-lenth fields.
    @fixed_length = []
  end

  # Add syscall information, more precisely its content and information about
  # the buffer a received message (network packet) was stored in during tracing.
  # @param [Integer] buf_addr buffer address
  # @param [Integer] buf_size buffer length
  # @param [Integer] count actual size of the received message
  # @param [String] base64 encoded binary content of the message (buffer)
  def add_syscall(buf_addr, buf_size, count, msg, action=ACTION::CONTINUE)
    @te.add_tainted_mem!(buf_addr, count)
    @packets << {
      buf_addr: buf_addr,
      buf_size: buf_size,
      count: count,
      msg: Base64.decode64(msg),
      action: action
    }
  end

  # Expects an instruction state from the traversed instruction trace in order
  # to analyze it. First the state is used to spread taint and determine if its
  # operands are tainted. Afterwards the result from the taint engine is used
  # for further analysis in the inference engine.
  # @param is [InstructionState] instruction state from an execution trace
  def analyze_state(is)
    @te.get_tainted_ops(is)
    $log.debug("STATE:\n#{is.inspect}\n----------------------\n")
    cmp = @del_field.analyze_state(is)
    @dir_field.analyze_state(is)
    @dir_count_field.analyze_state(is, cmp)
    @fixlen_field.analyze_state(is)
  end

  # Triggers the inference of all fields. Is called when a message is finished.
  # Afterwards builds the model of the message by combining information,
  # retrieved from different inference objects.
  # @return [String] result of inferred model
  def infer_msg
    @dir_field.infer_fields
    @directions_targets = @dir_field.get_fields

    @del_field.infer_fields
    @delimiters = @del_field.get_fields

    @dir_count_field.infer_fields(@delimiters)
    @directions_counter_targets = @dir_count_field.get_fields

    @keyword_field.infer_fields(@del_field.get_successful_cmps,
                                @del_field.get_delimiter_addresses)
    @keywords = @keyword_field.get_fields

    # Direction/Target inference produces unreliable results, therefore, turend
    # off during final evaluation.
    #@fixlen_field.infer_fields(@directions_targets,
    #                           @directions_counter_targets)

    @fixlen_field.infer_fields([],
                               @directions_counter_targets)
    @fixlens = @fixlen_field.get_fields

    # Let the GC (hopefully) clean up unneeded heavy objects.
    @te = nil
    @dir_field = nil
    @dir_count_field = nil
    @del_field = nil
    @keyword_field = nil
    @fixlen_field = nil

    # Direction/Target inference produces unreliable results, therefore, turend
    # off during final evaluation.
    #@protocol_model = ProtocolModel.new(@packets, @delimiters, @keywords,
    #                                    @directions_targets,
    #                                    @directions_counter_targets,
    #                                    @fixlens)
    @protocol_model = ProtocolModel.new(@packets, @delimiters, @keywords,
                                        [],
                                        @directions_counter_targets,
                                        @fixlens)
    return @protocol_model.text_model
  end

end
