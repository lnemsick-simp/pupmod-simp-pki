Puppet::Type.type(:pki_cert_sync).provide(:redhat) do

  def initialize(args)
    super(args)
  end

  # Returns a hash of PEM files derived from the contents of the source
  # directory
  # - Each key is a relative file path to a valid PEM file or the
  #   generated, aggregate certificate PEM file, cacerts.pem
  # - The value of each key is the name of the top-level link for that
  #   PEM file.
  # - If the PEM file matches the link name, no link is required.
  #
  def source
    src = resource[:source]
    File.directory?(src) or fail Puppet::Error, "'#{src}' is not a valid directory."

    hash_targets = {}
    @to_link = {}
    @directories = []
    @concatted_certs = ''

    Dir.chdir(src) do
      # Get all the files, but not the symlinks or cacerts.pem.
      to_parse = Dir.glob('**/*').sort
      to_parse.delete_if{|x| File.symlink?(x)}
      to_parse.delete_if{|x| x == 'cacerts.pem' }

      # Get all of the directories for later use.
      @directories = to_parse.select { |x| File.directory?(x) }
      # Remove directories from to_parse, they don't belong in to_link!
      to_parse.delete_if{|x| File.directory?(x) }

      # Determine what they all hash to.
      to_parse.each do |file|
        begin
          cert = OpenSSL::X509::Certificate.new(File.read(file))
        rescue OpenSSL::X509::CertificateError
          # We had a problem, skip this file.
          Puppet.warning("File '#{file}' does not look like an X.509 certificate, skipping")
          next
        end

        @concatted_certs += IO.read(file)

        cert_hash = sprintf("%08x",cert.subject.hash)
        hash_targets[cert_hash] ||= Array.new

        file_prefix,file_suffix = file.split('.')
        if file_prefix == cert_hash
          hash_targets[cert_hash].insert(file_suffix.to_i,file)
        else
          i = 0
          while !hash_targets[cert_hash][i].nil? do i += 1 end
          hash_targets[cert_hash][i] = file
        end
      end
    end

    hash_targets.each_key do |cert_hash|
      i = 0
      hash_targets[cert_hash].each do |file|
        next if file == 'cacerts.pem'
        @to_link[file] = "#{cert_hash}.#{i}"
        i += 1
      end
    end

    @to_link['cacerts.pem'] = 'cacerts.pem'
    @to_link
  end

  # src = Hash returned by provider's source() with the following format:
  #   {
  #     PEM_file => link
  #     PEM_file2 => link2
  #     ...
  #   }
  #
  #   If the PEM file matches the link name, no link is required.
  #
  # target = directory in which certs listed in src should be found
  #
  # If :purge type parameter is set, the target should only contain
  # the certs listed in src
  def source_insync?(src,target)
    File.directory?(target) or Dir.mkdir(target, 0755)

    insync = true
    Dir.chdir(target) do

      # If we're purging, and the number of files is different, then we're
      # not in sync.
      files = Dir.glob('**/*').select { |f| File.file?(f) }
      if @resource.purge? and files.count != src.to_a.flatten.uniq.count
        Puppet.debug("Different number of files from #{resource[:source]} to #{resource[:name]}")
        insync = false
        break
      end

      # If we're purging, and the list of directories is different, then we're
      # not in sync.
      if @resource.purge?
        dirs = Dir.glob('**/*').select { |d| File.directory?(d) }
        unless dirs.uniq.sort == @directories.uniq.sort
          Puppet.debug("Different number of directories from #{resource[:source]} to #{resource[:name]}")
          insync = false
          break
        end
      end

      # If the target does not have a file name that is in the source,
      # then we're not in sync.
      src.each_key do |k|
        unless files.include?(k)
          Puppet.debug("Not all files in #{resource[:source]} are found #{resource[:name]}")
          insync = false
          break
        end
      end

      break unless insync

      #TODO Should we check if the link for a PEM file is missing?

      # If all files have the same name, then we need to compare each one.
      src.each_key do |file|
        if file == 'cacerts.pem'
          #FIXME if the existing cacerts.pem was generated with a different
          # value of @resource.strip_cacerts_headers?, we should regenerate
          # the cacerts.pem
        else
          # Don't compare if the source file no longer exists
          # (i.e., file was removed between the time the directory was
          # scanned and this check is being executed...)
          if File.file?(file) && file_diff(file,"#{resource[:source]}/#{file}")
            Puppet.debug("File contents differ between #{resource[:source]} and #{resource[:name]}")
            insync = false
            break
          end
        end
      end

    end

    insync
  end

  def source=(should)
    # If the PEM file has the same name as the link, do not create a new link,
    # just copy the file.

    Dir.chdir(resource[:name]) do

      # Purge ALL THE THINGS
      if @resource.purge?
        # Make sure not to delete directories or certs (and symlinks) that we might currently be using.
        (Dir.glob('**/*') - [@to_link.to_a].flatten - @directories.flatten).each do |to_purge|
          unless ([@to_link.to_a].flatten).any? { |s| s.include?(to_purge) }
            Puppet.notice("Purging '#{resource[:name]}/#{to_purge}'")
            # Ensure the file still exists.  If a file's subdirectory was purged first
            # it won't be there.
            FileUtils.rm_rf(to_purge) if File.exists?(to_purge)
          end
        end
      end

      # This is simply a canary file to get File['/etc/pki/cacerts'] to trigger
      # a change for all those lovely legacy files out there. Should be
      # deprecated at some point since it's basically noise.
      FileUtils.touch('.sync_updated')
      FileUtils.chmod(0644, '.sync_updated')
      # End garbage hacky code

      generate_cacerts_pem(@concatted_certs, @resource.strip_cacerts_headers?)

      # Take care of directories first; make them if they don't already exist.
      @directories.each do |dir|
        FileUtils.mkdir_p(dir)
      end

      # Now copy over those items that differ and link them.
      @to_link.each_pair do |src,link|
        if File.exist?(src)
          selinux_context = resource.get_selinux_current_context("#{resource[:name]}/#{src}")
        else
          selinux_context = resource.get_selinux_current_context("#{resource[:source]}/#{src}")
        end

        selinux_context.nil? and
          Puppet.debug("Could not get selinux context for '#{resource[:source]}/#{src}'")

        unless src == 'cacerts.pem'
          FileUtils.cp("#{resource[:source]}/#{src}",src,{:preserve => true})
          resource.set_selinux_context("#{resource[:name]}/#{src}",selinux_context).nil? and
            Puppet.debug("Could not set selinux context on '#{src}'")

          # Only link if the names are different.
          if src != link
            FileUtils.ln_sf(src,link)
            # Have to set the SELinux context here too since symlinks can have
            # different contexts than files.
            resource.set_selinux_context("#{resource[:name]}/#{link}",selinux_context).nil? and
              Puppet.debug("Could not set selinux context on link '#{link}'")
          end
        end
      end
    end
  end

  # Helper Methods

  # Ok, this is definitely not DRY since this is in concat_build. However, I
  # haven't found a consistent way of having a common library of junk for
  # custom types to use. Perhaps I should start collecting these into a simp
  # package.

  # Does a comparison of two files and returns true if they differ and false if
  # they do not.
  def file_diff(src, dest)
    unless File.exist?(src)
      fail Puppet::Error,"Could not diff nonexistent source file #{src}."
    end

    # If the destination isn't there, it's different.
    return true unless File.exist?(dest)

    # If the sizes are different, it's different.
    return true if File.stat(src).size != File.stat(dest).size

    # If we've gotten here, brute force by 512B at a time. Stop when a chunk differs.
    s_file = File.open(src,'r')
    d_file = File.open(dest,'r')

    retval = false
    while not s_file.eof? do
      if s_file.read(512) != d_file.read(512)
        retval = true
        break
      end
    end

    s_file.close
    d_file.close
    return retval
  end

  # Generate a file containing 0 or more PEM-formatted X.509
  # certificates in the target directory.
  # The file will be named 'cacerts.pem'.
  #
  # content_raw = list of one or more PEM-formatted X.509 certificates
  # strip_cacerts_headers = whether to strip X.509 headers
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

    unless File.exists?(cacerts_file)
      File.open(cacerts_file, 'w') {|f| f.write(content)}
      File.chmod(0644, cacerts_file)
    else
      !(IO.read(cacerts_file).eql? content) and
          File.open(cacerts_file, 'w') {|f| f.write(content)}
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
end
