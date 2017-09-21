# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
# Defines an interface for all classes responsible for field inference.
# @abstract
class AbstractFieldInference
  # Constructor, initializes internal objects for all subclasses involved in the
  # inference step.
  def initializes
    raise NotImplementedError
  end

  # Add an tainted instruction which is relevant for inference of a field.
  # If instruction not relevant then return false. If the instruction/state was
  # saved for processing return true.
  # @param ins_state [Hash] instruction state from the trace
  # @param t_ops [Array] tainted operands
  # @return [Boolean] true if the instruction state was relevant for field
  # inference
  def analyze_state(ins_state, t_ops)
    raise NotImplementedError
  end

  # Triggers the inference after the whole trace was analyzed
  def infer_fields
    raise NotImplementedError
  end

  # Getter for the results
  # returns [Array] inferred fields
  def get_fields
    raise NotImplementedError
  end
end
