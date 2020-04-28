# frozen_string_literal: true

require 'test_helper'
require 'smart_proxy_dhcp_dnsmasq/dhcp_dnsmasq_subnet_service'

class DHCPDnsmasqSubnetServiceTest < Test::Unit::TestCase
  def setup
    @subnet_service = mock
    Dir.stubs(:exist?).returns(true)
  end

  def test_initialize
    subnet = ::Proxy::DHCP::Subnet.new('10.0.0.0', '255.255.255.0')
    host = ::Proxy::DHCP::Reservation.new('test', '10.0.0.10', 'ba:be:fa:ce:ca:fe', subnet)
    lease = ::Proxy::DHCP::Lease.new('test', '10.0.0.10', 'ba:be:fa:ce:ca:fe', subnet, Time.now, Time.now + 1000, 'active')

    initializer = Proxy::DHCP::Dnsmasq::SubnetService.new(
      'config/file', 'config/dir', 'lease/file',
      ::Proxy::MemoryStore.new, ::Proxy::MemoryStore.new,
      ::Proxy::MemoryStore.new, ::Proxy::MemoryStore.new,
      ::Proxy::MemoryStore.new
    )

    initializer.expects(:add_subnet).with(subnet)
    initializer.expects(:add_host)
    initializer.expects(:add_lease)

    initializer.expects(:parse_config_for_subnets).returns([subnet])
    initializer.expects(:parse_config_for_dhcp_reservations).returns([host])
    initializer.expects(:load_leases).returns([lease])
    # initializer.expects(:add_watch)

    initializer.load!
  end

  def test_load_fixtures
    service = Proxy::DHCP::Dnsmasq::SubnetService.new(
      Dir['test/fixtures/config/dnsmasq*.conf'], 'test/fixtures/config/dhcp', 'test/fixtures/config/dhcp.leases',
      ::Proxy::MemoryStore.new, ::Proxy::MemoryStore.new,
      ::Proxy::MemoryStore.new, ::Proxy::MemoryStore.new,
      ::Proxy::MemoryStore.new
    )

    assert service.load!

    subnet_id = service.subnets.keys[0]
    subnet = service.subnets[subnet_id]
    assert_not_nil subnet
    assert_equal '192.168.0.0', subnet.network
    assert_equal '255.255.255.0', subnet.netmask
    assert_equal IPAddr.new('192.168.0.0/24'), subnet.ipaddr
    assert_equal ['192.168.0.200', '192.168.0.223'], subnet.options[:range]
    assert_equal ['192.168.0.1'], subnet.options[:domain_name_servers]
    assert_equal '192.168.0.1-192.168.0.254', subnet.range

    subnet_id = service.subnets.keys[1]
    subnet = service.subnets[subnet_id]
    assert_not_nil subnet
    assert_equal '10.0.0.0', subnet.network
    assert_equal '255.255.255.0', subnet.netmask
    assert_equal IPAddr.new('10.0.0.0/24'), subnet.ipaddr
    assert_equal ['10.0.0.200', '10.0.0.254'], subnet.options[:range]
    assert_equal ['10.0.0.1'], subnet.options[:domain_name_servers]
    assert_equal '10.0.0.1-10.0.0.254', subnet.range

    subnet_id = service.subnets.keys[2]
    subnet = service.subnets[subnet_id]
    assert_not_nil subnet
    assert_equal '192.168.2.0', subnet.network
    assert_equal '255.255.255.0', subnet.netmask
    assert_equal IPAddr.new('192.168.2.0/24'), subnet.ipaddr
    assert_equal ['192.168.2.2', '192.168.2.254'], subnet.options[:range]
    assert_equal ['192.168.2.1'], subnet.options[:domain_name_servers]
    assert_equal ['192.168.2.1'], subnet.options[:routers]
    assert_equal '192.168.2.1-192.168.2.254', subnet.range

    # 3 in dnsmasq.conf
    # 4 in dnsmasq-2.conf
    # 1 in dhcphosts/
    assert_equal 8, service.reservations_by_name.values.count

    reservation = service.find_host_by_hostname('host1')
    assert_not_nil reservation
    assert_equal '00:11:22:33:44:55', reservation.mac
    assert_equal 'pxelinux.0', reservation.options[:filename]
    assert_equal '192.168.0.2', reservation.options[:nextServer]

    assert_equal 15, service.leases_by_ip.values.count

    lease = service.find_lease_by_ip('192.168.0.0', '192.168.0.3')
    assert_not_nil lease
    assert_equal '44:fa:23:05:1b:8b', lease.mac
    assert_equal 'active', lease.state
  end
end
