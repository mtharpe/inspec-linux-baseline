# frozen_string_literal: true

class SUIDCheck < Inspec.resource(1)
  name 'suid_check'
  desc 'Verify the current SUID/SGID files on the system against a denylist.'
  example <<~EXAMPLE
    describe suid_check(denylist) do
      its('diff') { should be_empty }
    end
  EXAMPLE

  FIND_CMD = %q(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    ! -path '/proc/*' ! -path '/var/lib/lxd/containers/*' \
    -print 2>/dev/null | grep -v '^find:').freeze

  def initialize(denylist = nil)
    @denylist = denylist && !denylist.empty? ? denylist : inspec.suid_denylist.default
  end

  def permissions
    @permissions ||= inspec.command(FIND_CMD).stdout.split(/\r?\n/)
  end

  def diff
    permissions & @denylist
  end

  def to_s
    'SUID/SGID denylist check'
  end
end
