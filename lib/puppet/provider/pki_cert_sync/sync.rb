Puppet::Type.type(:pki_cert_sync).provide(:redhat) do

  def initialize(args)
    super(args)
  end

  def source
    src = resource[:source]
    File.directory?(src) or fail Puppet::Error, "'#{src}' is not a valid directory."

    @generate_cacerts = @resource.generate_cacerts_file? or
      (@src_cacerts_file and @resource.strip_cacerts_headers?)

    hash_targets = {}
    @to_link = {}
    @directories = []
    @concatted_certs = ''

    Dir.chdir(src) do
      to_parse = Dir.glob('**/*').sort
      @src_cacerts_file = to_parse.include?('cacerts.pem')

      # Get all the files, but not the symlinks or cacerts.pem.
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

        @concatted_certs += IO.read(file) if @resource.generate_cacerts_file?

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

    if @resource.generate_cacerts_file? || @src_cacerts_file
      # cacerts.pem needs to be in the target directory, so make sure it
      # is in the list of files to examine in source_insync?() and purged
      # in source=()
      @to_link['cacerts.pem'] = 'cacerts.pem'
    end

    @to_link
  end

  # src = Hash returned by provider's source() with the following format:
  #   PEM_file -> link
  #   PEM_file2 -> link2
  #   ...
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
      if files.count != src.to_a.flatten.uniq.count and @resource.purge?
        Puppet.debug("Different number of files from #{resource[:source]} to #{resource[:name]}")
        insync = false
      end

      # If we're purging, and the list of directories is different, then we're
      # not in sync.
      if @resource.purge?
        dirs = Dir.glob('**/*').select { |d| File.directory?(d) }
        unless dirs.uniq.sort == @directories.uniq.sort
          Puppet.debug("Different number of directories from #{resource[:source]} to #{resource[:name]}")
          insync = false
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


      # If all files have the same name, then we need to compare each one.
      src.each_key do |file|
        next if ( (file == 'cacerts.pem') && @generate_cacerts )
        # If we've gotten here, we need to exclude any target that doesn't
        # exist for the purge settings.
        if File.file?(file) && file_diff(file,"#{resource[:source]}/#{file}")
          Puppet.debug("File contents differ between #{resource[:source]} and #{resource[:name]}")
          insync = false
          break
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

      # cacerts.pem is special...
      handle_cacerts_file

      # Take care of directories first; make them if they don't already exist.
      @directories.each do |dir|
        FileUtils.mkdir_p(dir)
      end

      # Now copy over those items that differ and link them.
      @to_link.each_pair do |src,link|
        unless src == 'cacerts.pem'
          selinux_context = get_selinux_context(src)
          copy_file(src, selinux)

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

  # copy file from the source directory to the target directory
  # and attempt to set its Selinux context to selinux_context
  #
  # Fails if file does not exist in the source directory
  def copy_file(file, selinux_context)
    source = File.join(resource[:source], file)
    dest = File.join(resource[:name], file)
    FileUtils.cp(source, dest, {:preserve => true})
    resource.set_selinux_context(dest, selinux_context).nil? and
      Puppet.debug("Could not set selinux context on '#{dest}'")
  end

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

  def generate_cacerts_file
    unless @resource.generate_cacerts_file?
      @concatted_certs = IO.read(File.join(resource[:source], 'cacerts.pem'))
    end

    if @resource.strip_cacerts_headers?
      content = strip_x509_headers(@concatted_certs)
    else
      content = @concatted_certs
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
  end

  def get_selinux_context(file)
    if File.exist?(file)
      selinux_context = resource.get_selinux_current_context("#{resource[:name]}/#{file}")
    else
      selinux_context = resource.get_selinux_current_context("#{resource[:source]}/#{file}")
    end

    selinux_context.nil? and
      Puppet.debug("Could not get selinux context for '#{resource[:source]}/#{file}'")

    selinux_context
  end

  def handle_cacerts_file
    if @generate_cacerts
      generate_cacerts_file
    elsif @src_cacerts_file
      copy_file('cacerts.pem', get_selinux_context('cacerts.pem'))
    end
  end

  # Returns the contents of an X509 certificate with the headers stripped
  def strip_x509_headers(cert_raw)
    begin_regex = /^#{Regexp.escape('-----BEGIN CERTIFICATE-----')}$/
    end_regex = /^#{Regexp.escape('-----END CERTIFICATE-----')}$/

    cert_lines = []
    cert_begin_found = false
    cert_raw.split("\n").each do |line|
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
