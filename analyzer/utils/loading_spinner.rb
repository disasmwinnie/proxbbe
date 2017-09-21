# Used to show spinner as a progress bar.
# @author Sergej Schmidt (sergej.schmidt at uni-ulm.de)
class LoadingSpinner
  # Prepares the spinner.
  def initialize
    @spinner = ['|','/','-','\\'].cycle
    @is_running = false
  end

  # Creates a new thread, which prints a spinner progress bar to stdout.
  # The thread runs as long as the @is_running var is true.
  def start
    @is_running = true
    @t = Thread.new do
      while @is_running
        STDERR.print("  " + @spinner.next + "\r")
        $stderr.flush
        sleep(0.1)
      end
    end
  end
  # Stops the progress bar thread.
  def stop
    @is_running = false
    @t.join
  end
end
