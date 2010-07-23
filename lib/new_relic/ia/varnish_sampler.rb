require 'new_relic/ia/metric_names'

# Varnish stats sampler
class NewRelic::IA::VarnishSampler < NewRelic::Agent::Sampler

  include NewRelic::IA::MetricNames
  case RUBY_PLATFORM
  when /darwin/
    # Do some special stuff...
  when /linux/
    # Do some special stuff...
  else
    NewRelic::IA::CLI.log.warn "unsupported platform #{RUBY_PLATFORM}"
  end

  def initialize
    super 'varnish'
    @int_values = [ :total_requests, :cache_hits, :cache_misses ]
    @derivatives = [:hit_ratio, :miss_ratio, :rpm, :hpm, :mpm]

    @last_stats = Hash.new
    @varnish_nodes = parse_config
  end

  def parse_config
    # file with a list of varnish nodes. each line have hostname
    varnish_nodes = NewRelic::Control.instance['varnish_nodes']
    if !varnish_nodes.is_a? Array || varnish_nodes.empty?
      raise NewRelic::IA::InitError, "No varnish_nodes array found in newrelic.yml."
    end
    varnish_nodes
  end

  def varnish_nodes
    @varnish_nodes
  end

  # Sanity check, make sure the servers are there.
  def check
    down_servers = []
    varnish_nodes.each do | hostname |
      stats_text = issue_stats hostname
      down_servers << hostname unless stats_text
    end
    raise NewRelic::Agent::Sampler::Unsupported, "Servers not available: #{down_servers.join(", ")}" unless down_servers.empty?
  end

  # This gets called once a minute in the agent worker thread.  It
  # pings each host in the array 'varnish_nodes'
  def poll
    unless varnish_nodes.empty?
      varnish_nodes.each do | hostname |
        stats_text = issue_stats hostname
        if stats_text
          @last_stats[hostname] = parse_and_report_stats hostname, stats_text
        else
          @last_stats[hostname] = nil #{}
        end        
      end

      aggregate_stats
      debug "done with aggs"    
    end
  end

  def logger
    NewRelic::IA::CLI.log
  end

  def aggregate_stats
    begin
      aggs_stats = Hash.new
      @int_values.each {|metric| aggs_stats[metric] = 0}

      @derivatives[0,2].each {|metric| aggs_stats[metric] = 0.0}
      @derivatives[2,@derivatives.length - 2].each {|metric| aggs_stats[metric] = 0}

      aggs_count = 0
      @last_stats.each_value do |v|
        @int_values.each do |metric|
          aggs_stats[metric] +=  (v[metric] || 0)
        end
        if v[:hit_ratio] && v[:miss_ratio]
          @derivatives[0,2].each do |metric|
            aggs_stats[metric] +=  v[metric]
          end
          aggs_count += 1

          @derivatives[2,@derivatives.length - 2].each do |metric|
            aggs_stats[metric] +=  v[metric]
          end
        end
      end
      if aggs_count > 0
        aggs_stats[:hit_ratio] = aggs_stats[:hit_ratio] /aggs_count
        aggs_stats[:miss_ratio] = aggs_stats[:miss_ratio] /aggs_count
      end

      @int_values.each do |stat|
        debug "recording #{VARNISH}/all/#{stat.to_s} = #{aggs_stats[stat]}"
        begin
          stats("#{VARNISH}/all/#{stat.to_s}").record_data_point(aggs_stats[stat])
        rescue => e
          debug "Could not record stat: #{stat}\n #{e.backtrace.join("\n")}"
        end
      end
      if aggs_count > 0
        @derivatives.each do |stat|
          debug "recording #{VARNISH}/all/#{stat.to_s} = #{aggs_stats[stat].to_i}"
          begin
            stats("#{VARNISH}/all/#{stat.to_s}").record_data_point(aggs_stats[stat].to_i)
          rescue => e
            debug "Could not record stat: #{stat}\n #{e.backtrace.join("\n")}"
          end
        end
      end

    rescue => e
      debug "Could not record stat: stats\n #{e.backtrace.join("\n")}"
    end
  end


  def issue_stats(hostname)
    debug  "get stats from hostname #{hostname}"
    begin
      lookup_url = "http://#{hostname}/varnish?cmd=stats"
      url = URI.parse(lookup_url)
      res = Net::HTTP.start(url.host, url.port) {|http|
        http.get("/varnish?cmd=stats")
      }
      statistics = res.body
      if !statistics || statistics.length == 0
        break
      end
      start_index = statistics =~ /200 3262/
      if start_index != 0
        NewRelic::IA::CLI.log.warn "varnish: unexpected stats output from #{hostname_port}: #{statistics}"
        logger.info "varnish: unable to connect to varnish node at #{hostname_port}"
        break
      end
      end_index = statistics =~ /\n\n/
      if end_index
        return statistics
      end
    rescue SocketError => e
      NewRelic::IA::CLI.log.warn "varnish: unable to connect to varnish node at #{hostname}: #{e.message}"
      logger.info "varnish: unable to connect to varnish node at #{hostname}"
      logger.error "varnish: #{e.message}"
      debug e.backtrace.join("\n")
    end
    nil
  end

  def parse_stats(hostname, stats_text)
    start_index = stats_text =~ /\n/
    end_index = stats_text =~ /\n\n/
    stats_text = stats_text[start_index ... stats_text.length].strip if start_index
    stats_text = stats_text[0 ... end_index].strip if end_index
    
    stats_array = stats_text.split(/\s\s+/)
    if stats_array.size % 2 != 0
      logger.error "varnish: unexpected stats output from #{hostname}: #{stats_text}"
      break
    end
    tuples = []
    while stats_array.any? do
      tuples << [ stats_array.shift, stats_array.shift]
    end
    stats = Hash.new
    tuples.each do |tuple|
      debug "#{tuple[1].gsub(/\W+/, '_').downcase.to_sym} = #{tuple[0]}"
      stats[tuple[1].gsub(/\W+/, '_').downcase.to_sym] = tuple[0]
    end
    return stats
  end

  def parse_and_report_stats(hostname, stats_text)
    # client_connections_accepted = 2833
    # connection_dropped_no_sess = 0
    # client_requests_received = 1193
    # cache_hits = 704
    # cache_hits_for_pass = 0
    # cache_misses = 437
    # backend_conn_success = 489
    # backend_conn_not_attempted = 0
    # backend_conn_too_many = 0
    # backend_conn_failures = 0
    # backend_conn_reuses = 0
    # backend_conn_was_closed = 0
    # backend_conn_recycles = 0
    # backend_conn_unused = 0
    # fetch_head = 0
    # fetch_with_length = 489
    # fetch_chunked = 0
    # fetch_eof = 0
    # fetch_had_bad_headers = 0
    # fetch_wanted_close = 0
    # fetch_pre_http_1_1_closed = 0
    # fetch_zero_len = 0
    # fetch_failed = 0
    # n_struct_srcaddr = 0
    # n_active_struct_srcaddr = 0
    # n_struct_sess_mem = 7
    # n_struct_sess = 1
    # n_struct_object = 17
    # n_struct_objecthead = 18
    # n_struct_smf = 36
    # n_small_free_smf = 1
    # n_large_free_smf = 4
    # n_struct_vbe_conn = 0
    # n_struct_bereq = 3
    # n_worker_threads = 10
    # n_worker_threads_created = 10
    # n_worker_threads_not_created = 0
    # n_worker_threads_limited = 43553
    # n_queued_work_requests = 0
    # n_overflowed_work_requests = 0
    # n_dropped_work_requests = 0
    # n_backends = 2
    # n_expired_objects = 423
    # n_lru_nuked_objects = 0
    # n_lru_saved_objects = 0
    # n_lru_moved_objects = 536
    # n_objects_on_deathrow = 0
    # http_header_overflows = 0
    # objects_sent_with_sendfile = 0
    # objects_sent_with_write = 1109
    # objects_overflowing_workspace = 0
    # total_sessions = 2833
    # total_requests = 1193
    # total_pipe = 0
    # total_pass = 52
    # total_fetch = 489
    # total_header_bytes = 481727
    # total_body_bytes = 87651673
    # session_closed = 2448
    # session_pipeline = 0
    # session_read_ahead = 0
    # session_linger = 1193
    # session_herd = 913
    # shm_records = 88466
    # shm_writes = 24614
    # shm_flushes_due_to_overflow = 0
    # shm_mtx_contention = 0
    # shm_cycles_through_buffer = 1
    # allocator_requests = 979
    # outstanding_allocations = 31
    # bytes_allocated = 569344
    # bytes_free = 104288256
    # sma_allocator_requests = 0
    # sma_outstanding_allocations = 0
    # sma_outstanding_bytes = 0
    # sma_bytes_allocated = 0
    # sma_bytes_free = 0
    # sms_allocator_requests = 0
    # sms_outstanding_allocations = 0
    # sms_outstanding_bytes = 0
    # sms_bytes_allocated = 0
    # sms_bytes_freed = 0
    # backend_requests_made = 489
    # n_vcl_total = 1
    # n_vcl_available = 1
    # n_vcl_discarded = 0
    # n_total_active_purges = 293
    # n_new_purges_added = 695
    # n_old_purges_deleted = 402
    # n_objects_tested = 274
    # n_regexps_tested_against = 5398
    # n_duplicate_purges_removed = 479
    # hcb_lookups_without_lock = 0
    # hcb_lookups_with_lock = 0
    # hcb_inserts = 0
    # objects_esi_parsed_unlock_ = 0
    # esi_parse_errors_unlock_ = 0


    #     need to compute during collection
    #     * Hit Ratio (%)
    #     * Requests per interval
    #     * Hits per interval
    #     * Misses per interval

    stats = parse_stats(hostname, stats_text)

    #we store ints in the hash
    @int_values.each do |stat| 
      stats[stat] = stats[stat].to_i 
    end
    #time is not shipped to collector but we add it for derivative calculations
    stats[:time] = Time.now
    
    previous_stats = @last_stats[hostname]
    if previous_stats
      tn = stats[:time]
      tm = previous_stats[:time] 
       
      #unit per minute 
      stats[:rpm] = (stats[:total_requests] - previous_stats[:total_requests]) / (tn - tm) * 60 
      stats[:hpm] = (stats[:cache_hits] - previous_stats[:cache_hits]) / (tn - tm) * 60
      stats[:mpm] = (stats[:cache_misses] - previous_stats[:cache_misses]) / (tn - tm) * 60
      if stats[:hpm] + stats[:mpm] > 0
        stats[:hit_ratio] = stats[:hpm] / (stats[:hpm]+stats[:mpm])*100
        stats[:miss_ratio] = stats[:mpm] / (stats[:hpm]+stats[:mpm])*100
      else
        stats[:hit_ratio] = 100
        stats[:miss_ratio] = 0
      end
    end
    
    @int_values.each do |stat| 
      debug "recording #{VARNISH}/#{hostname}/#{stat.to_s} = #{stats[stat]}"
      begin
        stats("#{VARNISH}/#{hostname}/#{stat.to_s}").record_data_point(stats[stat])
      rescue => e
        debug "Could not record stat: #{stat}\n #{e.backtrace.join("\n")}"
      end
    end
    if previous_stats
      @derivatives.each do |stat|
        begin
          value = stats[stat].to_i
          debug "recording #{VARNISH}/#{hostname}/#{stat.to_s} = #{value}"
          stats("#{VARNISH}/#{hostname}/#{stat.to_s}").record_data_point(value)
        rescue => e
          puts "Error converting #{stat} value <#{stats[stat]}> to i: #{e.message}"
          puts "stats: #{stats.inspect}"
          debug "Could not record stat: #{stat}\n #{e.backtrace.join("\n")}"
        end
      end
    end

    debug "Done with record data"
    return stats
  end
  
  def stats(s)
    NewRelic::Agent.get_stats_no_scope(s)
  end
  
  def debug(msg)
    logger.debug "varnish: #{msg}"
  end
end

