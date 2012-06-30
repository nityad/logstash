require "logstash/inputs/threadable"
require "logstash/namespace"
require "socket" # for Socket.gethostname

# Generate random log events.
#
# The general intention of this is to test performance of plugins.
#
# An event is generated first
class LogStash::Inputs::Generator < LogStash::Inputs::Threadable
  config_name "generator"
  plugin_status "experimental"

  # The message string to use in the event.
  #
  # If you set this to 'stdin' then this plugin will read a single line from
  # stdin and use that as the message string for every event.
  #
  # Otherwise, this value will be used verbatim as the event message.
  config :message, :validate => :string, :default => "Hello world!"

  public
  def register
    @host = Socket.gethostname
    @metric_generate = @logger.metrics.timer(self, "event-generation")
    @metric_queue_write = @logger.metrics.timer(self, "queue-write-time")
  end # def register

  def run(queue)
    number = 0
    source = "generator://#{@host}/"

    if @message == "stdin"
      @logger.info("Generator plugin reading a line from stdin")
      @message = $stdin.readline
      @logger.debug("Generator line read complete", :message => @message)
    end

    while !finished?
      event = to_event(@message, source)
      event["sequence"] = number
      number += 1
      queue << event
    end # loop
  end # def run

  public
  def teardown
    finished
  end # def teardown
end # class LogStash::Inputs::Stdin
