# frozen_string_literal: true

login_defs_umask = input(
  'login_defs_umask',
  value: os.redhat? ? '077' : '027',
  description: 'Default umask in /etc/login.defs'
)
login_defs_passmaxdays = input('login_defs_passmaxdays')
login_defs_passmindays = input('login_defs_passmindays')
login_defs_passwarnage = input('login_defs_passwarnage')
suid_denylist_input = input('suid_denylist')

shadow_group =
  if os.debian? || os.suse? || os.name == 'alpine'
    'shadow'
  else
    'root'
  end

container_execution = virtualization.role == 'guest' &&
                      %w[lxc docker].include?(virtualization.system)

control 'os-01' do
  impact 1.0
  title 'Trusted hosts login'
  desc 'hosts.equiv is a weak authentication mechanism that lets users bypass normal access controls.'
  tag category: 'os'
  tag cis: '5.4'

  describe file('/etc/hosts.equiv') do
    it { should_not exist }
  end
end

control 'os-02' do
  impact 1.0
  title 'Check owner and permissions for /etc/shadow'
  desc 'Periodically verify the owner and permissions on /etc/shadow.'
  tag category: 'os'
  tag cis: '6.1.3'

  describe file('/etc/shadow') do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    its('group') { should eq shadow_group }
    it { should_not be_executable }
    it { should_not be_readable.by('other') }
  end

  if os.redhat? || os.name == 'fedora'
    describe file('/etc/shadow') do
      it { should_not be_writable.by('owner') }
      it { should_not be_readable.by('owner') }
    end
  else
    describe file('/etc/shadow') do
      it { should be_writable.by('owner') }
      it { should be_readable.by('owner') }
    end
  end

  if os.debian? || os.suse?
    describe file('/etc/shadow') do
      it { should be_readable.by('group') }
    end
  else
    describe file('/etc/shadow') do
      it { should_not be_readable.by('group') }
    end
  end
end

control 'os-03' do
  impact 1.0
  title 'Check owner and permissions for /etc/passwd'
  desc 'Periodically verify the owner and permissions on /etc/passwd.'
  tag category: 'os'
  tag cis: '6.1.4'

  describe file('/etc/passwd') do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
    it { should_not be_executable }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should be_readable.by('owner') }
    it { should be_readable.by('group') }
    it { should be_readable.by('other') }
  end
end

control 'os-04' do
  impact 1.0
  title 'Dot in PATH variable'
  desc 'The current working directory must not be present in PATH; this would let an attacker execute trojaned binaries.'
  tag category: 'os'

  describe os_env('PATH') do
    its('split') { should_not include('') }
    its('split') { should_not include('.') }
  end
end

control 'os-05' do
  impact 1.0
  title 'Check login.defs'
  desc 'Verify owner, permissions, PATH, umask and password-aging values in /etc/login.defs.'
  tag category: 'os'

  describe file('/etc/login.defs') do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    its('group') { should eq 'root' }
    it { should_not be_executable }
    it { should be_readable.by('owner') }
    it { should be_readable.by('group') }
    it { should be_readable.by('other') }
  end

  describe login_defs do
    its('ENV_SUPATH') { should include('/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin') }
    its('ENV_PATH')   { should include('/usr/local/bin:/usr/bin:/bin') }
    its('UMASK')         { should include(login_defs_umask) }
    its('PASS_MAX_DAYS') { should eq login_defs_passmaxdays }
    its('PASS_MIN_DAYS') { should eq login_defs_passmindays }
    its('PASS_WARN_AGE') { should eq login_defs_passwarnage }
    its('LOGIN_RETRIES') { should eq '5' }
    its('LOGIN_TIMEOUT') { should eq '60' }
    its('UID_MIN')       { should eq '1000' }
    its('GID_MIN')       { should eq '1000' }
  end
end

control 'os-05b' do
  impact 1.0
  title 'Check login.defs - RedHat specific'
  desc 'RedHat-family-specific login.defs requirements (system UID/GID ranges and immutability).'
  only_if('Only applicable to RedHat-family systems') { os.redhat? }
  tag category: 'os'

  describe file('/etc/login.defs') do
    it { should_not be_writable }
  end

  describe login_defs do
    its('SYS_UID_MIN') { should eq '201' }
    its('SYS_UID_MAX') { should eq '999' }
    its('SYS_GID_MIN') { should eq '201' }
    its('SYS_GID_MAX') { should eq '999' }
  end
end

control 'os-06' do
  impact 1.0
  title 'Check for SUID/SGID denylist'
  desc 'Find denylisted SUID/SGID files to ensure no rogue SUID/SGID files have been introduced.'
  tag category: 'os'

  describe suid_check(suid_denylist_input) do
    its('diff') { should be_empty }
  end
end

control 'os-07' do
  impact 1.0
  title 'Unique uid and gid'
  desc 'Verify that all UIDs and GIDs are unique.'
  tag category: 'os'

  describe passwd do
    its('uids') { should_not contain_duplicates }
  end

  describe etc_group do
    its('gids') { should_not contain_duplicates }
  end
end

control 'os-08' do
  impact 1.0
  title 'Entropy'
  desc 'The system should have at least 1000 bits of available entropy.'
  tag category: 'os'

  entropy = file('/proc/sys/kernel/random/entropy_avail').content.to_i
  describe 'available entropy' do
    subject { entropy }
    it { should be >= 1000 }
  end
end

control 'os-09' do
  impact 1.0
  title 'Check for .rhosts and .netrc files'
  desc 'CIS 9.2.9-10: no .rhosts or .netrc files should exist on the system.'
  tag category: 'os'
  tag cis: '6.2.2'

  output = command('find / -maxdepth 3 \( -iname .rhosts -o -iname .netrc \) -print 2>/dev/null | grep -v \'^find:\'')
  describe output.stdout.split(/\r?\n/) do
    it { should be_empty }
  end
end

control 'os-10' do
  impact 1.0
  title 'CIS: Disable unused filesystems'
  desc '1.1.1 Ensure mounting of cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, FAT.'
  only_if('Skipped in containers') { !container_execution }
  tag category: 'os'
  tag cis: '1.1.1'

  efi_active = file('/sys/firmware/efi').exist?

  modules = %w[cramfs freevxfs jffs2 hfs hfsplus squashfs udf]
  modules << 'vfat' unless efi_active

  modules.each do |mod|
    describe kernel_module(mod) do
      it { should_not be_loaded }
      it { should be_disabled }
    end
  end
end

control 'os-11' do
  impact 1.0
  title 'Protect log directory'
  desc '/var/log must be owned by root.'
  tag category: 'os'

  describe file('/var/log') do
    it { should be_directory }
    it { should be_owned_by 'root' }
    its(:group) { should match(/^root|syslog$/) }
  end
end
