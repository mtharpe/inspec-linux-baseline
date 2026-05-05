# frozen_string_literal: true

syslog_pkg = input('syslog_pkg')
container_execution = virtualization.role == 'guest' &&
                      %w[lxc docker].include?(virtualization.system)

control 'package-01' do
  impact 1.0
  title 'Do not run deprecated inetd or xinetd'
  desc 'inetd/xinetd are legacy super-servers and should not be installed.'
  ref 'NSA RHEL5 STIG 3.2.1', url: 'https://www.nsa.gov/'
  tag category: 'package'

  describe package('inetd') do
    it { should_not be_installed }
  end

  describe package('xinetd') do
    it { should_not be_installed }
  end
end

control 'package-02' do
  impact 1.0
  title 'Do not install Telnet server'
  desc 'Telnet transmits credentials in cleartext.'
  ref 'NSA RHEL5 STIG 3.2.2'
  tag category: 'package'

  describe package('telnetd') do
    it { should_not be_installed }
  end
end

control 'package-03' do
  impact 1.0
  title 'Do not install rsh server'
  desc 'r-commands suffer the same cleartext problem as telnet.'
  ref 'NSA RHEL5 STIG 3.2.3'
  tag category: 'package'

  describe package('rsh-server') do
    it { should_not be_installed }
  end
end

# package-04 is reserved.

control 'package-05' do
  impact 1.0
  title 'Do not install ypserv server (NIS)'
  desc 'NIS does not adequately protect authentication information.'
  ref 'NSA RHEL5 STIG 3.2.4'
  tag category: 'package'

  describe package('ypserv') do
    it { should_not be_installed }
  end
end

control 'package-06' do
  impact 1.0
  title 'Do not install tftp server'
  desc 'tftp-server provides little security.'
  ref 'NSA RHEL5 STIG 3.2.5'
  tag category: 'package'

  describe package('tftp-server') do
    it { should_not be_installed }
  end
end

control 'package-07' do
  impact 1.0
  title 'Install syslog server package'
  desc 'A syslog server is required to receive system and application logs. Skipped on Fedora (uses systemd-journald) and inside containers.'
  only_if('Skipped on Fedora and in containers') { os.name != 'fedora' && !container_execution }
  tag category: 'package'

  describe package(syslog_pkg) do
    it { should be_installed }
  end
end

control 'package-08' do
  impact 1.0
  title 'Install auditd'
  desc 'auditd provides extended logging capabilities on recent distributions.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'package'
  tag cis: '4.1.1'

  audit_pkg =
    if os.redhat? || os.suse? || os.name == 'amazon' || os.name == 'fedora'
      'audit'
    else
      'auditd'
    end

  describe package(audit_pkg) do
    it { should be_installed }
  end

  describe auditd_conf do
    its('log_file')                { should cmp '/var/log/audit/audit.log' }
    its('log_format')              { should cmp 'raw' }
    its('flush')                   { should match(/^incremental|INCREMENTAL|incremental_async|INCREMENTAL_ASYNC$/) }
    its('max_log_file_action')     { should cmp 'keep_logs' }
    its('space_left')              { should cmp 75 }
    its('action_mail_acct')        { should cmp 'root' }
    its('space_left_action')       { should cmp 'SYSLOG' }
    its('admin_space_left')        { should cmp 50 }
    its('admin_space_left_action') { should cmp 'SUSPEND' }
    its('disk_full_action')        { should cmp 'SUSPEND' }
    its('disk_error_action')       { should cmp 'SUSPEND' }
  end
end

control 'package-09' do
  impact 1.0
  title 'CIS: Additional process hardening'
  desc '1.5.4 Ensure prelink is disabled.'
  tag category: 'package'
  tag cis: '1.5.4'

  describe package('prelink') do
    it { should_not be_installed }
  end
end
