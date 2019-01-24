Puppet::Type.newtype(:pki_cert_strip) do
  require 'puppet/parameter/boolean'
  require 'puppet/util/selinux'
  require 'puppet/util/symbolic_file_mode'
  include Puppet::Util::SELinux
  include Puppet::Util::SymbolicFileMode

  @doc = <<-EOM
    A puppet type to create a copy of a PEM file that does not have
    X.509 headers.  The source file can contain 0 or more X.509
    certificates.

    Usage:

    pki_cert_strip { '<target PEM file>': source => '<source PEM file>' }

    Both files must exist on the local operating system, as remote file
    syncing is not supported.
  EOM

  def initialize(args)
    super(args)

    if self[:tag] then
      self[:tag] += ['pki']
    else
      self[:tag] = ['pki']
    end
  end

  def finish
    # Do stuff here if necessary after the catalog compiles.

    super
  end

  newparam(:name, :namevar => true) do
    desc = <<-EOM
      The name of the target certificate file
    EOM

    validate do |value|
      Puppet::Util.absolute_path?(value) or
        fail Puppet::Error, "Target file must be an absolute path, not '#{value}'"
    end
  end

  newparam(:fail_if_missing, :boolean => true, :parent => Puppet::Parameter::Boolean) do
    desc = <<-EOM
      Whether to fail if the source PEM file does not exist.

      When you cannot be assured the source file is present, set this
      to false.  This will affect the copy when the source file is
      present, but do nothing otherwise.
    EOM

    defaultto true
  end

  newparam(:owner) do
    desc = <<-EOM
      The user to which the file should belong.  Can be a string or an
      integer.  When not set, defaults to the owner attribute of the
      source file.
    EOM
  end

  newparam(:group) do
    desc = <<-EOM
      Which group should own the file.  Can be a string or an integer.
      When not set, defaults to the group attribute of source file.
    EOM
  end

  newparam(:mode) do
    desc = <<-EOM
      The desired permissions of the file specified as a numeric or
      symbolic string.  For example '0755' or 'u=rwx,g=rx,o=rx'.
      When not set, defaults to the mode attribute of source file.
    EOM

    validate do |value|
      if value
        Puppet::Util::SymbolicFileMode.valid_symolic_mode?(value) or
          fail(Puppet::Error, "Invalid mode '#{value}'")
      end
    end

    munge do |value|
      symbolic_mode_to_int(value, Puppet::Util::DEFAULT_POSIX_MODE)
    end
  end

  newparam(:seltype) do
    desc = <<-EOM
      The desired SELinux type context of the file specified as a numeric or
      symbolic string.  For example '0755' or 'u=rwx,g=rx,o=rx'.
      When not set, defaults to the SeLinux type context of the source file.
    EOM
  end

  newproperty(:source) do
    desc = <<-EOM
      The source PEM file
    EOM

    validate do |value|
      Puppet::Util.absolute_path?(value) or
        fail Puppet::Error, "Source must be an absolute path, not '#{value}'"
    end

    # is = hash of info about the source file or nil if the source file
    #      does not exist
    def insync?(is)
      if is.nil? and resource[:fail_if_missing]
        fail Puppet::Error, "Source file '#{resource[:source]}' does not exist"
      end

      # compare info about the source file with the target file
      provider.source_insync?(is,resource[:name])
    end

  end

  autorequire(:file) do
    [ self[:source] ]
  end

  autonotify(:file) do
    [ self[:name] ]
  end
end
