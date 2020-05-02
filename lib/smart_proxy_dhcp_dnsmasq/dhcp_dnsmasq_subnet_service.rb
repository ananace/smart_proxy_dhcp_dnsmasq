# frozen_string_literal: true

require 'ipaddr'
require 'pathname'
require 'rb-inotify'
require 'dhcp_common/dhcp_common'
require 'dhcp_common/subnet_service'
require 'smart_proxy_dhcp_dnsmasq/dhcp_dnsmasq_utils'

module Proxy::DHCP::Dnsmasq
  class SubnetService < ::Proxy::DHCP::SubnetService
    include Proxy::Log

    OPTSFILE_CLEANUP_INTERVAL = 15 * 60 # 15 minutes

    attr_accessor :last_cleanup
    attr_reader :config_dir, :lease_file

    def initialize(config, target_dir, lease_file, leases_by_ip, leases_by_mac, reservations_by_ip, reservations_by_mac, reservations_by_name)
      @config_paths = [config].flatten
      @target_dir = target_dir
      @lease_file = lease_file

      # Must be an absolute path for the inotify watch to succeed at the moment
      @lease_file = File.expand_path(@lease_file) unless (Pathname.new @lease_file).absolute?

      super(leases_by_ip, leases_by_mac, reservations_by_ip, reservations_by_mac, reservations_by_name)
    end

    def load!
      # TODO: Refresh data if outdated
      return true if subnets.any?

      parse_config_for_subnets.each { |s| add_subnet(s) }
      load_subnet_data

      true
    end

    def watch_leases
      logger.info "Watching leases in file #{lease_file}"
      @inotify = INotify::Notifier.new
      @inotify.watch(File.dirname(lease_file), :modify, :moved_to) do |ev|
        next unless ev.absolute_name == lease_file

        leases = load_leases

        m.synchronize do
          leases_by_ip.clear
          leases_by_mac.clear

          leases.each do |record|
            subnet_address = record.subnet_address

            leases_by_ip[subnet_address, record.ip] = record
            leases_by_mac[subnet_address, record.mac] = record
          end
        end
      end

      @inotify.run
    rescue INotify::QueueOverflowError => e
      logger.warn "Queue overflow occured when monitoring #{lease_file}, restarting monitoring", e
      sleep 60
      retry
    rescue StandardError => e
      logger.error "Error occured when monitoring #{lease_file}", e
    end

    def start
      Thread.new { watch_leases }
    end

    def stop
      @inotify&.stop
    end

    def cleanup_time?
      Time.now - (@last_cleanup ||= Time.now) > OPTSFILE_CLEANUP_INTERVAL
    end

    def parse_config_for_subnets
      configuration = { }
      files = []
      @config_paths.each do |path|
        if File.directory? path
          files += Dir[File.join(path, '*')]
        else
          files << path
        end
      end

      interfaces = Socket.getifaddrs.select { |i| Proxy::DHCP::Dnsmasq.net_iface? i }.sort { |i| i.ifindex }
      available_interfaces = nil
      domain = nil

      logger.debug "Starting parse of DHCP subnets from #{files}"
      files.each do |file|
        logger.debug "  Parsing #{file}..."
        File.open(file, 'r').each_line.with_index do |line, line_nr|
          line.strip!
          next if line.empty? || line.start_with?('#') || !line.include?('=')

          option, value = line.split('=')

          option.strip!
          value.strip!

          case option
          when 'interface'
            iface = interfaces.find { |i| i.name == value }
            (available_interfaces ||= []) << iface if iface
          when 'no-dhcp-interface'
            (available_interfaces ||= interfaces).delete_if { |i| i.name == value }
          when 'domain'
            domain = value
          when 'dhcp-leasefile'
            next if @lease_file

            @lease_file = value
          when 'dhcp-range'
            data = value.split(',')

            # Parse parameters
            tags = Proxy::DHCP::Dnsmasq.parse_tags(data)

            initial_arg = data.shift if /^\w+$/ =~ data.first
            start_addr = IPAddr.new(data.shift)
            end_addr = data.shift if /^((\d{1,3}\.){3}\d{1,3}|(\a+:+)+(\a+))|(static|constructor:\w+)$/ =~ data.first
            if start_addr.ipv4?
              netmask = data.shift if /^(\d{1,3}\.){3}\d{1,3}$/ =~ data.first
              broadcast = data.shift if /^(\d{1,3}\.){3}\d{1,3}$/ =~ data.first
            else
              mode = data.shift if /^([a-z-]+,)*([a-z-]+)$/ =~ data.first
              prefix_len = data.shift if /^\d+$/ =~ data.first
            end
            lease_time = data.shift if data.first =~ /^\d+[mhd]|infinite|deprecated$/

            if start_addr.ipv6? # Smart-proxy currently doesn't support IPv6
              logger.warning "Skipping IPv6 subnet found on line #{line_nr}."
              next
            end

            logger.warning "Failed to fully parse line #{file}:#{line_nr}: '#{line}', unparsed data: #{data.inspect}" unless data.empty?

            ipv4 = start_addr.ipv4?
            subnet_iface = interfaces.find { |i| (ipv4 ? i.addr.ipv4? : i.addr.ipv6?) && i.name == subnet_iface } if initial_arg
            initial_arg = nil if subnet_iface
            subnet_iface ||= interfaces.find do |i|
              IPAddr.new("#{i.addr.ip_address}/#{i.netmask.ip_address}").include? start_addr
            end

            # Make sure to always have a name for all subnets
            subnet_id = initial_arg
            subnet_id ||= subnet_iface.name if subnet_iface
            subnet_id ||= tags.set
            subnet_id ||= 'default'

            mask = netmask
            mask ||= subnet_iface.netmask.ip_address if subnet_iface
            if !mask && ipv4
              mask ||= '255.0.0.0' if IPAddr.new('10.0.0.0/8').include? start_addr
              mask ||= '255.255.0.0' if IPAddr.new('172.16.0.0/12').include? start_addr
              mask ||= '255.255.255.0'
            elsif !mask
              mask ||= prefix_len
            end

            ttl = case lease_time[-1]
                  when 'd'
                    lease_time[0..-2].to_i * 24 * 60 * 60
                  when 'h'
                    lease_time[0..-2].to_i * 60 * 60
                  when 'm'
                    lease_time[0..-2].to_i * 60
                  else
                    lease_time.to_i
                  end if lease_time
            ttl ||= 1 * 60 * 60 # Default lease time is one hour

            subnet_data = (configuration[subnet_id] ||= {})
            subnet_data.merge! \
              interface: subnet_iface&.name,
              address: IPAddr.new("#{start_addr}/#{mask}").to_s,
              broadcast: broadcast,
              mask: mask,
              mode: mode,
              range: [start_addr.to_s, end_addr].compact,
              ttl: ttl

            (subnet_data[:options] ||= {}).merge! \
              range: subnet_data[:range]

            subnet_data[:options][:domain_name] = domain if domain

            # TODO: Handle this in a better manner
            @ttl = subnet_data[:ttl]
          when 'dhcp-option'
            data = value.split(',')
            tags = Proxy::DHCP::Dnsmasq.parse_tags(data)

            subnet_ids = tags.tags.empty? ? nil : tags.tags
            subnet_ids ||= data.first if configuration.keys.include? data.first
            subnet_ids ||= data.first if interfaces.find { |i| i.name == data.first }
            subnet_ids ||= configuration.keys

            data.shift until data.empty? || /^\d+|option6?:\w+$/ =~ data.first
            next if data.empty?

            unless data.first =~ /^\d+$/
              logger.warning "Found non-numeric DHCP option on line #{file}:#{line_nr}: '#{line}', skipping."
              next
            end
            code = data.shift.to_i

            option = ::Proxy::DHCP::Standard.select { |_k, v| v[:code] == code }
            if option.any?
              option = option.keys.first
              data = data.first unless ::Proxy::DHCP::Standard[option][:is_list]
            else
              option = code
            end

            [subnet_ids].flatten.each do |id|
              ((configuration[id] ||= {})[:options] ||= {})[option] = data
            end
          end
        end
      end

      subnets = []
      configuration.each do |id, data|
        next unless data[:address] && data[:mask]

        logger.debug "Parsed subnet #{id} (#{data[:address]}) with configuration; #{data}"
        subnet = ::Proxy::DHCP::Subnet.new(data[:address], data[:mask], data[:options])
        yield subnet if block_given?
        subnets << subnet
      end
      subnets
    end

    # Expects subnet_service to have subnet data
    def parse_config_for_dhcp_reservations
      to_ret = {}
      files = []

      @config_paths.each do |path|
        if File.directory? path
          files += Dir[File.join(path, '*')]
        else
          files << path
        end
      end

      logger.debug "Starting parse of DHCP reservations from #{files}"
      files.each do |file|
        logger.debug "  Parsing #{file}..."
        File.open(file, 'r').each_line do |line|
          line.strip!
          next if line.empty? || line.start_with?('#') || !line.include?('=')

          option, value = line.split('=')
          case option
          when 'dhcp-host'
            data = value.split(',')
            Proxy::DHCP::Dnsmasq.parse_tags(data)

            mac, ip, hostname = data[0, 3]

            # Handle alternative ordering
            if ip =~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/
              mac, ip = [ip, mac]
            end

            # TODO: Possible ttl on end

            subnet = find_subnet(ip)
            to_ret[mac] = ::Proxy::DHCP::Reservation.new(
              hostname,
              ip,
              mac,
              subnet
              # :source_file => file # TODO: Needs to overload the comparison
            )
          when 'dhcp-boot'
            data = value.split(',')
            tags = Proxy::DHCP::Dnsmasq.parse_tags(data)
            next if tags.tags.empty?

            mac = tags.tags.find { |t| /^(\w{2}:){5}\w{2}$/ =~ t }
            next if mac.nil?

            file, server = data

            to_ret[mac].options[:nextServer] = server
            to_ret[mac].options[:filename] = file
          end
        end
      end
      dhcpoptions = {}

      dhcpopts_path = File.join(@target_dir, 'dhcpopts.conf')
      logger.debug "Parsing DHCP options from #{dhcpopts_path}"
      if File.exist? dhcpopts_path
        File.open(dhcpopts_path, 'r').each_line do |line|
          data = line.strip.split(',')
          next if data.empty? || !data.first.start_with?('tag:')

          tags = Proxy::DHCP::Dnsmasq.parse_tags(data)
          dhcpoptions[tags.tag] = data.last
        end
      end

      logger.debug "Parsing provisioned DHCP reservations from #{@target_dir}"
      Dir[File.join(@target_dir, 'dhcphosts', '*')].each do |file|
        logger.debug "  Parsing #{file}..."
        File.open(file, 'r').each_line do |line|
          data = line.strip.split(',')
          next if data.empty? || data.first.start_with?('#')

          mac = data.first
          data.shift

          options = { deletable: true }
          tags = Proxy::DHCP::Dnsmasq.parse_tags(data)
          tags.sets.each do |tag|
            value = dhcpoptions[tag]
            next if value.nil?

            options[:nextServer] = value if tag.start_with? 'ns'
            options[:filename] = value if tag.start_with? 'bf'
          end

          ip, name = data
          subnet = find_subnet(ip)

          to_ret[mac] = ::Proxy::DHCP::Reservation.new(
            name, ip, mac, subnet, options
          )
        end
      end

      to_ret.values
    rescue StandardError => e
      logger.error msg = "Unable to parse reservations: #{e}"
      raise Proxy::DHCP::Error, e, msg
    end

    def load_subnet_data
      reservations = parse_config_for_dhcp_reservations
      reservations.each do |record|
        if (dupe = find_host_by_mac(record.subnet_address, record.mac))
          logger.debug "Found duplicate #{dupe} when adding record #{record}, skipping"
          next
        end

        # logger.debug "Adding host #{record}"
        add_host(record.subnet_address, record)
      end

      leases = load_leases
      leases.each do |lease|
        if (dupe = find_lease_by_mac(lease.subnet_address, lease.mac))
          logger.debug "Found duplicate #{dupe} by MAC when adding lease #{lease}, skipping"
          next
        end
        if (dupe = find_lease_by_ip(lease.subnet_address, lease.ip))
          logger.debug "Found duplicate #{dupe} by IP when adding lease #{lease}, skipping"
          next
        end

        # logger.debug "Adding lease #{lease}"
        add_lease(lease.subnet_address, lease)
      end
    end

    # Expects subnet_service to have subnet data
    def load_leases
      raise 'No subnets configured' unless subnets.any?

      File.open(@lease_file, 'r').readlines.map do |line|
        timestamp, mac, ip, _hostname, _client_id = line.split
        timestamp = timestamp.to_i

        subnet = find_subnet(ip)
        ::Proxy::DHCP::Lease.new(
          nil, ip, mac, subnet,
          timestamp - (@ttl || 24 * 60 * 60),
          timestamp,
          'active'
        )
      end.compact
    rescue StandardError => e
      logger.error 'Unable to load leases', e
      []
    end
  end
end
