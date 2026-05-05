# frozen_string_literal: true

sysctl_forwarding = input('sysctl_forwarding')
ipv6_disabled = input('ipv6_disabled')
kernel_modules_disabled = input('kernel_modules_disabled')

container_execution = virtualization.role == 'guest' &&
                      %w[lxc docker].include?(virtualization.system)

# Helper for the very common single-key sysctl assertion.
def expect_kparam(key, value)
  describe kernel_parameter(key) do
    its(:value) { should eq value }
  end
end

control 'sysctl-01' do
  impact 1.0
  title 'IPv4 Forwarding'
  desc 'If the system is not a router, IPv4 forwarding must be disabled.'
  only_if('Skipped when forwarding is required or in containers') do
    sysctl_forwarding == false && !container_execution
  end
  tag category: 'sysctl'

  expect_kparam('net.ipv4.ip_forward', 0)
  expect_kparam('net.ipv4.conf.all.forwarding', 0)
end

control 'sysctl-02' do
  impact 1.0
  title 'Reverse path filtering'
  desc 'rp_filter rejects packets whose source address does not match the receiving interface, mitigating spoofing.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.conf.all.rp_filter', 1)
  expect_kparam('net.ipv4.conf.default.rp_filter', 1)
end

control 'sysctl-03' do
  impact 1.0
  title 'ICMP ignore bogus error responses'
  desc 'Drop bogus ICMP responses to prevent log spam.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.icmp_ignore_bogus_error_responses', 1)
end

control 'sysctl-04' do
  impact 1.0
  title 'ICMP echo ignore broadcasts'
  desc 'Block ICMP ECHO requests to broadcast addresses.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.icmp_echo_ignore_broadcasts', 1)
end

control 'sysctl-05' do
  impact 1.0
  title 'ICMP ratelimit'
  desc 'icmp_ratelimit defines how many packets matching icmp_ratemask are allowed per second.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.icmp_ratelimit', 100)
end

control 'sysctl-06' do
  impact 1.0
  title 'ICMP ratemask'
  desc 'ICMP ratemask is a logical OR of all ICMP codes to rate-limit.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.icmp_ratemask', 88_089)
end

control 'sysctl-07' do
  impact 1.0
  title 'TCP timestamps'
  desc 'Disabling TCP timestamps prevents external uptime fingerprinting.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.tcp_timestamps', 0)
end

control 'sysctl-08' do
  impact 1.0
  title 'ARP ignore'
  desc 'Reply only if the target IP address is local to the receiving interface.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.conf.all.arp_ignore', 1)
end

control 'sysctl-09' do
  impact 1.0
  title 'ARP announce'
  desc 'Use the best local address for ARP announcements (mode 2).'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.conf.all.arp_announce', 2)
end

control 'sysctl-10' do
  impact 1.0
  title 'TCP RFC1337 (protect against TCP time-wait assassination)'
  desc 'Drop RST packets for sockets in the TIME-WAIT state.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.tcp_rfc1337', 1)
end

control 'sysctl-11' do
  impact 1.0
  title 'Protection against SYN flood attacks'
  desc 'Enable SYN cookies to mitigate SYN-flood DoS.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.tcp_syncookies', 1)
end

control 'sysctl-12' do
  impact 1.0
  title 'Shared media IP architecture'
  desc 'Send/accept RFC1620 shared-media redirects.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.conf.all.shared_media', 1)
  expect_kparam('net.ipv4.conf.default.shared_media', 1)
end

control 'sysctl-13' do
  impact 1.0
  title 'Disable source routing'
  desc 'Source-routed packets allow MITM via reply interception; reject them.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.conf.all.accept_source_route', 0)
  expect_kparam('net.ipv4.conf.default.accept_source_route', 0)
end

control 'sysctl-14' do
  impact 1.0
  title 'Disable acceptance of all IPv4 redirected packets'
  desc 'Block ICMP redirects to prevent MITM attacks.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.conf.default.accept_redirects', 0)
  expect_kparam('net.ipv4.conf.all.accept_redirects', 0)
end

control 'sysctl-15' do
  impact 1.0
  title 'Disable acceptance of secure-redirected packets'
  desc 'Even "secure" ICMP redirects can enable MITM attacks.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.conf.all.secure_redirects', 0)
  expect_kparam('net.ipv4.conf.default.secure_redirects', 0)
end

control 'sysctl-16' do
  impact 1.0
  title 'Disable sending of redirect packets'
  desc 'Hosts (non-routers) must not send ICMP redirects.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.conf.default.send_redirects', 0)
  expect_kparam('net.ipv4.conf.all.send_redirects', 0)
end

control 'sysctl-17' do
  impact 1.0
  title 'Log martian packets'
  desc 'Log packets with impossible source addresses to assist forensics.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv4.conf.all.log_martians', 1)
  expect_kparam('net.ipv4.conf.default.log_martians', 1)
end

control 'sysctl-18' do
  impact 1.0
  title 'Disable IPv6 if it is not needed'
  desc 'Disable IPv6 entirely on systems that do not use it.'
  only_if('Only enforced when ipv6_disabled input is true') do
    ipv6_disabled == true && !container_execution
  end
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.all.disable_ipv6', 1)
end

control 'sysctl-19' do
  impact 1.0
  title 'IPv6 Forwarding'
  desc 'If the system is not a router, IPv6 forwarding must be disabled.'
  only_if('Skipped when forwarding is required or in containers') do
    sysctl_forwarding == false && !container_execution
  end
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.all.forwarding', 0)
end

control 'sysctl-20' do
  impact 1.0
  title 'Disable acceptance of all IPv6 redirected packets'
  desc 'Block IPv6 ICMP redirects to prevent MITM attacks.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.default.accept_redirects', 0)
  expect_kparam('net.ipv6.conf.all.accept_redirects', 0)
end

control 'sysctl-21' do
  impact 1.0
  title 'Disable acceptance of IPv6 router solicitations'
  desc 'With static addressing there is no need to send router solicitations.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.default.router_solicitations', 0)
end

control 'sysctl-22' do
  impact 1.0
  title 'Disable router-preference acceptance from RAs'
  desc 'Ignore Accept Router Preference values from router advertisements.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.default.accept_ra_rtr_pref', 0)
end

control 'sysctl-23' do
  impact 1.0
  title 'Disable learning Prefix Information from RAs'
  desc 'accept_ra_pinfo controls whether to accept prefix info from a router.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.default.accept_ra_pinfo', 0)
end

control 'sysctl-24' do
  impact 1.0
  title 'Disable learning Hop Limit from RAs'
  desc 'Prevent a router from changing the system default IPv6 Hop Limit.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.default.accept_ra_defrtr', 0)
end

control 'sysctl-25' do
  impact 1.0
  title 'Disable acceptance of router advertisements'
  desc 'Reject router advertisements entirely.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.all.accept_ra', 0)
  expect_kparam('net.ipv6.conf.default.accept_ra', 0)
end

control 'sysctl-26' do
  impact 1.0
  title 'Disable IPv6 autoconfiguration'
  desc 'Prevent RAs from triggering global unicast address assignment.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.default.autoconf', 0)
end

control 'sysctl-27' do
  impact 1.0
  title 'Disable per-address neighbor solicitations'
  desc 'dad_transmits controls how many neighbor solicitations are sent per address; 0 disables.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.default.dad_transmits', 0)
end

control 'sysctl-28' do
  impact 1.0
  title 'Limit global unicast IPv6 addresses to one per interface'
  desc 'max_addresses controls how many global unicast IPv6 addresses can be assigned per interface.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('net.ipv6.conf.default.max_addresses', 1)
end

control 'sysctl-29' do
  impact 1.0
  title 'Disable loading kernel modules'
  desc 'kernel.modules_disabled=1 prevents loading new kernel modules, blocking malicious module loads.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('kernel.modules_disabled', kernel_modules_disabled)
end

control 'sysctl-30' do
  impact 1.0
  title 'Magic SysRq'
  desc 'kernel.sysrq exposes a powerful key combination; disable it.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('kernel.sysrq', 0)
end

control 'sysctl-31a' do
  impact 1.0
  title 'Secure core dumps - dump settings'
  desc 'Ensure core dumps cannot be made by setuid programs.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  describe kernel_parameter('fs.suid_dumpable') do
    its(:value) { should cmp(/(0|2)/) }
  end
end

control 'sysctl-31b' do
  impact 1.0
  title 'Secure core dumps - dump path'
  desc 'When fs.suid_dumpable=2, core_pattern must be a fully qualified path.'
  only_if('Only when fs.suid_dumpable=2 and not in a container') do
    kernel_parameter('fs.suid_dumpable').value == 2 && !container_execution
  end
  tag category: 'sysctl'

  describe kernel_parameter('kernel.core_pattern') do
    its(:value) { should match %r{^\|?/.*} }
  end
end

control 'sysctl-32' do
  impact 1.0
  title 'kernel.randomize_va_space'
  desc 'Full ASLR: kernel.randomize_va_space must be 2.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  expect_kparam('kernel.randomize_va_space', 2)
end

control 'sysctl-33' do
  impact 1.0
  title 'CPU NX flag or kernel ExecShield'
  desc 'CPU NX or kernel exec-shield prevents per-page code execution. NX is preferred when supported.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'sysctl'

  cpuinfo = parse_config_file('/proc/cpuinfo', assignment_regex: /^([^:]*?)\s+:\s+(.*?)$/)
  flags = cpuinfo['flags'].to_s.split

  describe '/proc/cpuinfo' do
    it 'flags should include NX' do
      expect(flags).to include('nx')
    end
  end

  unless flags.include?('nx')
    expect_kparam('kernel.exec-shield', 1)
  end
end
