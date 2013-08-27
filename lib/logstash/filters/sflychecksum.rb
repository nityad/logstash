require "logstash/filters/base"
require "logstash/namespace"
require "yaml"

# This filter let's you create a checksum based on various parts
# of the logstash event.
# This can be useful for deduplication of messages or simply to provide
# a custom unique identifier.
#
# This is VERY experimental and is largely a proof-of-concept
class LogStash::Filters::Sflychecksum < LogStash::Filters::Base

  config_name "sflychecksum"
  plugin_status "beta"
  # A list of keys to use in creating the string to checksum
  # Keys will be sorted before building the string
  # keys and values will then be concatenated with pipe delimetersn
  # and checksummed
  config :keys, :validate => :hash, :default => {}

  config :algorithm, :validate => ["md5", "sha128", "sha256", "sha384"], :default => "sha256"

  public
  def register
    require 'openssl'
  end

  public
  def filter(event)
    return unless filter?(event)

    @logger.debug("Running checksum filter", :event => event)
    @to_checksum = ""
    pattern = /\w*\d[\d\w]*/
    @keys.each do |k, value|
      @logger.debug("Current key and value", :current_key => k, :current_value => value)
      cur = event[k]
      @logger.debug("current value", :current_value => cur)
      if value and !cur.nil?
        if cur.kind_of?(Array)
          cur = cur.join(" ")
        end
        @logger.debug("patterned")
        cur = cur.gsub(pattern, "*")
      end
      @to_checksum << "#{cur} "
    event["@signature"] = @to_checksum
    end
    @logger.debug("Final string built", :to_checksum => @to_checksum)
    digested_string = OpenSSL::Digest.hexdigest(@algorithm, @to_checksum)
    @logger.debug("Digested string", :digested_string => digested_string)
    event['@checksum'] = digested_string
  end
end # class LogStash::Filters::Checksum
