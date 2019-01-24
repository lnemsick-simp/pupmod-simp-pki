Puppet::Type.type(:pki_cert_sync).provide(:redhat) do

  def initialize(args)
    super(args)
  end

  # Returns a hash of PEM files derived from the contents of the source
  # directory
  # - Each key is a relative file path to a valid PEM file or one of
  #   the generated, aggregate certificate PEM files, cacerts.pem and
  #   certs_no_headers.pem
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
      to_parse.delete_if{|x| x =~ /^cacerts(_no_headers)?.pem$/ }

      # Get all of the directories for later use.
      @directories = to_parse.select { |x| File.directory?(x) }
      # Remove directories from to_parse, they don't belong in to_link!
      to_parse.delete_if{|x| File.directory?(x) }

      # Load each PEM file, determine what it hashes to then add its
      # contents to expected files for cacerts.pem and cacerts_no_headers.pem
      target = resource[:name]
      File.directory?(target) or Dir.mkdir(target, 0755)
      exp_cacerts = File.open(File.join(target, '.cacerts.pem'), 'w', 0644)
      exp_stripped_cacerts = File.open(File.join(target, '.cacerts_no_headers.pem'), 'w', 0644)

      to_parse.sort.each do |file|
        begin
          raw_cert = File.read(raw_cert)
          cert = OpenSSL::X509::Certificate.new(raw_cert)
        rescue OpenSSL::X509::CertificateError
          # We had a problem, skip this file.
          Puppet.warning("File '#{file}' does not look like an X.509 certificate, skipping")
          next
        end

        exp_cacerts.write(raw_cert)
        exp_stripped_certs.write(strip_x509_headers(raw_cert))

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
        next if file =~ /^cacerts(_no_headers)?.pem$/
        @to_link[file] = "#{cert_hash}.#{i}"
        i += 1
      end
    end

    unless @to_link.empty?
      @to_link['cacerts.pem'] = 'cacerts.pem'
      @to_link['cacerts_no_headers.pem'] = 'cacerts_no_headers.pem'
    end
    @to_link
  ensure
    exp_cacerts.close if exp_cacerts
    exp_stripped_cacerts.close if exp_stripped_cacerts
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

      # If we're purging, and the number of files+links is different,
      # then we're not in sync.
      files = Dir.glob('**/*').select { |f| File.file?(f) }
      if @resource.purge? and files.count != src.to_a.flatten.uniq.count
        Puppet.debug("Different number of files from #{resource[:source]} to #{target}")
        insync = false
        break
      end

      # If we're purging, and directory trees are different, then we're
      # not in sync.
      if @resource.purge?
        dirs = Dir.glob('**/*').select { |d| File.directory?(d) }
        unless dirs.uniq.sort == @directories.uniq.sort
          Puppet.debug("#{resource[:source]} directory tree differs from #{target}")
          insync = false
          break
        end
      end

      # If the target does not have a source file name or its link,
      # then we're not in sync.
      src.each do |file, link|
        unless files.include?(file) and files.include?(link)
          Puppet.debug("Not all files in #{resource[:source]} are found in #{target}")
          insync = false
          break
        end
      end

      break unless insync

      # All expected files/links exist, but we need to verify each
      # {file,link} pair.
      src.each do |file, link|
        if file =~ /^cacerts(_no_headers)?.pem$/
          # Need to compare with the expected dot file we created in the
          # target directory in source()
          if files_different?(".#{file}",file)
            Puppet.debug("#{target}/#{file} is not current")
            insync = false
            break
          end
        else
          if files_different?("#{resource[:source]}/#{file}", file)
            Puppet.debug("File contents differ between #{resource[:source]} and #{target}")
            insync = false
            break
          end

          if !File.symlink?(link) or (File.readlink(link) != file)
            Puppet.debug("File links in #{target} are not current")
            insync = false
            break
          end
        end
      end

    end

    insync
  end

  def source=(should)

    Dir.chdir(resource[:name]) do

      # Purge ALL THE THINGS
      if @resource.purge?
        # Make sure not to delete directories or certs and their symlinks that we
        # might currently be using.
        (Dir.glob('**/*') - [@to_link.to_a].flatten - @directories.flatten).each do |to_purge|
          unless ([@to_link.to_a].flatten).any? { |s| s.include?(to_purge) }
            Puppet.notice("Purging '#{resource[:name]}/#{to_purge}'")
            # Use 'force' option in case a file's directory was purged first
            FileUtils.rm_rf(to_purge)
          end
        end
      end

      # This is simply a canary file to get File['/etc/pki/cacerts'] to trigger
      # a change for all those lovely legacy files out there. Should be
      # deprecated at some point since it's basically noise.
      # FIXME:  Is this still needed?
      FileUtils.touch('.sync_updated')
      FileUtils.chmod(0644, '.sync_updated')
      # End garbage hacky code

      # Take care of directories first; make them if they don't already exist.
      @directories.each do |dir|
        FileUtils.mkdir_p(dir)
      end

      # Now copy over all items and link them, as appropriate.
      @to_link.each_pair do |src,link|
        if src =~ /^cacerts(_no_headers)?.pem$/
          if File.exist?(src)
            selinux_context = resource.get_selinux_current_context("#{resource[:name]}/#{src}")
          else
            # The dot files were created using the default selinux context
            # for the target directory. We're going to assume that is appropriate.
            selinux_context = resource.get_selinux_current_context("#{resource[:name]}/.#{src}")
          end

          selinux_context.nil? and
            Puppet.debug("Could not get selinux context for '#{resource[:source]}/#{src}'")
          if File.exist?(".#{src}")
            FileUtils.cp(".#{src}",src,{:preserve => true})
            resource.set_selinux_context("#{resource[:name]}/#{src}",selinux_context).nil? and
              Puppet.debug("Could not set selinux context on '#{src}'")
          else
            Puppet.warning("Skipping sync of #{resource[:name]}/#{src}: Source no longer exists")
          end
        else
          if File.exist?("#{resource[:name]}/#{src}")
            if File.exist?(src)
              selinux_context = resource.get_selinux_current_context("#{resource[:name]}/#{src}")
            else
              selinux_context = resource.get_selinux_current_context("#{resource[:source]}/#{src}")
            end

            selinux_context.nil? and
              Puppet.debug("Could not get selinux context for '#{resource[:source]}/#{src}'")

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
          else
            Puppet.warning("Skipping sync of #{resource[:name]}/#{src}: Source no longer exists")
          end
        end
      end

      if @to_link.empty?
        # No managed certs. We need to make sure the aggregate PEM files
        # we create from those certs are removed, even when purging wasn't
        # enabled.
        Puppet.debug("Removing aggregate PEM files in #{resource[:name]}: No valid managed certificates")
        FileUtils.rm_f('cacerts.pem')
        FileUtils.rm_f('cacerts_no_headers.pem')
      end
    end
  end

  # Helper Methods

  # Does a comparison of two files
  # Returns true if either file is missing or they differ
  # Returns false if the files are the same
  def files_different?(src, dest)
    # If either file is missing, it's different
    return true unless (File.exist?(src) and File.exist?(dest))

    # This logic is nearly identical to that in FileUtils.compare_file(),
    # except it hardcodes the blocksize to a small value
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
    cert_lines.join("\n") + "\n"
  end
end
