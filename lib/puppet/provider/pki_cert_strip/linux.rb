Puppet::Type.type(:pki_cert_strip).provide(:linux) do
  confine :kernel => :linux
  defaultfor :kernel => :linux

  require 'puppet/util/posix'

  include Puppet::Util::POSIX

  def initialize(args)
    super(args)
  end

  # Returns hash of info about the source file or nil if the source file
  # does not exist
  def source
    source_pem = resource[:source]
    @info = nil
    if File.exist?(source_pem)
      stat = File.stat(source_pem)
      @info = {
        :content => strip_x509_headers(IO.read(source_pem)),
        :uid     => stat.uid,
        :gid     => stat.gid,
        :mode    => stat.mode,
        :seltype => resource.get_selinux_current_context(source_pem)
      }
    end

    @info
  end

  def source_insync?(src_info,target)
    return false unless File.exist?(target)

    target_stat = File.stat(target)

    desired_uid = resource[:owner] ? touid(resource[:owner]) : src_info[:uid]
    return false unless target_stat.uid == desired_uid

    desired_gid = resource[:group] ? togid(resource[:group]) : src_info[:gid]
    return false unless target_stat.uid == desired_gid

    desired_mode = resource[:mode] ? resource[:mode] : src_info[:mode]
    return false unless target_stat.mode == desired_mode

    desired_seltype = resource[:seltype] ? resource[:seltype] : src_info[:seltype]
    return false unless target_stat.seltype == desired_seltype

    return false unless IO.read(target) == src_info[:content]
    true
  end

  def source=(should)
    # All the info we need has been generated in the source() method and
    # saved in @info
    target_pem = resource[:name]
    unless File.exists?(target_pem)
      File.open(target_pem, 'w') {|f| f.write(@info[:content])}
      File.chmod(0644, target_pem)
    else
      !(IO.read(target_pem).eql? content) and
          File.open(cacerts_file, 'w') {|f| f.write(content)}
    end

  end

  # Generate a file containing 0 or more PEM-formatted X.509
  # certificates in the target directory.
  # The file will be named 'cacerts.pem'.
  #
  # content_raw = list of one or more PEM-formatted X.509 certificates
  # strip_cacerts_headers = whether to strip X.509 headers
  # FIXME put in a simp/util namespace for sharing
  #
  def generate_cacerts_pem(content_raw, strip_cacerts_headers)
    if strip_cacerts_headers
      content = strip_x509_headers(content_raw)
    else
      content = content_raw
    end

    cacerts_file = File.join(resource[:name], 'cacerts.pem')
    if content.strip.empty?
      Puppet.warning("File '#{cacerts_file}' is empty.")
    end

    #TODO Set selinux context?
  end

  # Strips any X.509 headers from a list of 0 or more PEM-formatted
  # X.509 certificates
  #
  # certs_raw = String containing list of certificates
  def strip_x509_headers(certs_raw)
    begin_regex = /^#{Regexp.escape('-----BEGIN CERTIFICATE-----')}$/
    end_regex = /^#{Regexp.escape('-----END CERTIFICATE-----')}$/

    cert_lines = []
    cert_begin_found = false
    certs_raw.split("\n").each do |line|
      if cert_begin_found
        cert_lines << line
        cert_begin_found = false if line.match(end_regex)
      else
        if line.match(begin_regex)
          cert_begin_found = true
          cert_lines << line
        end
      end
    end
    cert_lines.join("\n")
  end

  def touid(value)
    return value if value.is_a?(Integer)
    uid(value)
  end

  def togid(value)
    return value if value.is_a?(Integer)
    uid(value)
  end



end
