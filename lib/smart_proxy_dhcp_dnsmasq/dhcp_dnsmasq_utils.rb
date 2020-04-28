# frozen_string_literal: true

module Proxy::DHCP::Dnsmasq
  Tags = Struct.new(:tags, :sets) do
    def tag
      tags.first if tags.count == 1
    end

    def set
      sets.first if sets.count == 1
    end
  end

  def self.parse_tags(data)
    tags = { tags: [], sets: [] }
    while (matches = /(set|tag):([^,]+)/.match(data.first))
      if matches[1] == 'set'
        tags[:sets] << matches[2]
      else
        tags[:tags] << matches[2]
      end
      data.shift
    end
    Tags.new tags[:tags], tags[:sets]
  end

  def self.net_iface?(iface)
    ifaddr = iface.addr
    return unless ifaddr.ip?

    if ifaddr.ipv4?
      return if ifaddr.ipv4_multicast?
    else
      return if ifaddr.ipv6_linklocal? ||
                ifaddr.ipv6_multicast? ||
                ifaddr.ipv6_sitelocal?
    end

    true
  end
end
