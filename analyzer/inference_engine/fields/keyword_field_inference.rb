# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Responsible for inference of keyword fields.
# In contrast to direction or delimited field, this class does not analyze
# instruction by instruction, but only receives data from the delimiter-
# inference-step.
require_relative 'abstract_field_inference'

class KeywordFieldInference < AbstractFieldInference

  # Initializes instance variables
  def initialize
    @keyword_fields = []
  end

  # Analyzes the given data and infers the keyword fields.
  # @param suc_cmps [Hash] successful compares as addr => fixed_value
  # @param delimiter_addresses [Array] every element is a list with two elements:
  # first element is demlimiter as array, second is a the delimited byte range
  def infer_fields(suc_cmps, delimiter_addresses)
    consecutive_cmps = []
    addresses = suc_cmps.keys.sort
    last_keyword = []
    addresses.each do |addr|
      if delimiter_addresses.include?(addr)
        if !last_keyword.empty?
          consecutive_cmps << last_keyword
          last_keyword = []
        end
        next
        # Empty or consecutive byte.
      elsif last_keyword.empty? || last_keyword.last[0] == (addr-1)
        last_keyword << [addr, suc_cmps[addr]]
      else
        consecutive_cmps << last_keyword
        last_keyword = []
      end
    end

    consecutive_cmps.each do |cons_cmp|
      keyword = []
      cons_cmp.each {|n| keyword << n[1] }
      @keyword_fields << [keyword, Range.new(cons_cmp.first[0], cons_cmp.last[0])]
    end
  end

  # Returns the result of keyword inference.
  # @return [Array] array element: array, first is [keyword], second byte range
  def get_fields
    raise "You have to call infer_fields first" if @keyword_fields.nil?
    return @keyword_fields
  end
end
