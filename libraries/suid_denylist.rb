# frozen_string_literal: true

class SUIDDenylist < Inspec.resource(1)
  name 'suid_denylist'
  desc 'Returns the default list of files which should not have SUID/SGID bits set.'
  example <<~EXAMPLE
    describe suid_denylist do
      its('default') { should be_an(Array) }
    end
  EXAMPLE

  DEFAULT = [
    # NSA-published list
    '/usr/bin/rcp', '/usr/bin/rlogin', '/usr/bin/rsh',
    # sshd must not use host-based authentication
    '/usr/libexec/openssh/ssh-keysign',
    '/usr/lib/openssh/ssh-keysign',
    # misc
    '/sbin/netreport',
    '/usr/sbin/usernetctl',
    '/usr/sbin/userisdnctl',
    '/usr/sbin/pppd',
    '/usr/bin/lockfile',
    '/usr/bin/mail-lock',
    '/usr/bin/mail-unlock',
    '/usr/bin/mail-touchlock',
    '/usr/bin/dotlockfile',
    '/usr/bin/arping',
    '/usr/sbin/arping',
    '/usr/sbin/uuidd',
    '/usr/bin/mtr',
    '/usr/lib/evolution/camel-lock-helper-1.2',
    '/usr/lib/pt_chown',
    '/usr/lib/eject/dmcrypt-get-device',
    '/usr/lib/mc/cons.saver',
  ].freeze

  def default
    DEFAULT
  end
end
