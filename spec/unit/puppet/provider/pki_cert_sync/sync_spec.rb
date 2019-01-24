require 'spec_helper'
require 'tmpdir'


provider_class = Puppet::Type.type(:pki_cert_sync).provider(:redhat)

def populate_cert_dir(parent_dir, cert_files, debug = false)
  Dir.chdir(parent_dir) do
    cert_files.each do |cert_info|
      in_file, relative_path, dest_file = cert_info
      dest_file = File.basename(in_file) if dest_file.nil?

      dest_dir = File.join(parent_dir, relative_path)
      FileUtils.mkdir_p(dest_dir)
      FileUtils.cp(in_file, File.join(dest_dir, dest_file))
    end
  end
  puts `find #{parent_dir}` if debug
end

describe provider_class do
  let(:files_dir) { File.join(File.dirname(__FILE__), 'files') }
  let(:cert_subj_hash) do
    {
     :cert1 => '4a44b594',
     :cert2 => 'ae3116e1',
     :cert3 => 'db039224'
    }
  end

  let(:cert1_file) { File.join(files_dir, 'cert1.pem') }
  let(:cert1_no_hdrs_file) { File.join(files_dir, 'cert1_no_headers.pem') }
  let(:cert2_file) { File.join(files_dir, 'cert2.pem') }
  let(:cert3_no_hdrs_file) { File.join(files_dir, 'cert3_no_headers.pem') }
  let(:cacerts_file) { File.join(files_dir, 'cacerts.pem') }
  let(:cacerts_no_hdrs_file) { File.join(files_dir, 'cacerts_no_headers.pem') }

  # Test methods that do not rely upon internal provider state
  context 'stateless methods' do
    let(:provider) { resource.provider }
    let(:resource) do
      Puppet::Type.type(:pki_cert_sync).new({
        :name         => '/some/target/dir',
        :source       => '/some/source/dir',
        :provider     => 'redhat'
      })
    end

    describe 'files_different?' do
      it 'returns false when the files have the same content' do
        expect( provider.files_different?(cert1_file, cert1_file) ).to eq false
      end

      it 'returns true when the files have different content' do
        expect( provider.files_different?(cert1_file, cert2_file) ).to eq true
      end

      it 'returns true when either file does not exist' do
        expect( provider.files_different?('/does/not/exist', cert2_file) ).to eq true
        expect( provider.files_different?(cert1_file, '/does/not/exist') ).to eq true
        expect( provider.files_different?('/does/not/exist', '/does/not/exist') ).to eq true
      end
    end

    describe 'strip_x509_headers' do
      it 'strips headers from a single certificate' do
        expected = IO.read(cert1_no_hdrs_file)
        expect( provider.strip_x509_headers(IO.read(cert1_file)) ).to eq expected
      end

      it 'strips headers from multiple certificates' do
        expected = IO.read(cacerts_no_hdrs_file)
        expect( provider.strip_x509_headers(IO.read(cacerts_file)) ).to eq expected
      end

      it 'retains the content of a single certificate when no headers exist' do
        expected = IO.read(cert1_no_hdrs_file)
        expect( provider.strip_x509_headers(IO.read(cert1_no_hdrs_file)) ).to eq expected
      end

      it 'retains the content of multiple certificates when no headers exist' do
        expected = IO.read(cacerts_no_hdrs_file)
        expect( provider.strip_x509_headers(IO.read(cacerts_no_hdrs_file)) ).to eq expected
      end

      it 'returns and empty string when no certificates exist' do
        expect( provider.strip_x509_headers('') ).to eq ''
      end
    end

  end

  # Test remaining provider operation via sequences of source(),
  # source_insync?(), and source=() calls.  This testing approach is
  # required because the source() method generates internal and
  # external state info needed by the other methods.  The internal
  # state is stored in provider instance variables.  The external
  # state is written to dot files in the target directory.
  context 'stateful methods via scenarios' do
    before(:each) do
      @tmpdir = Dir.mktmpdir
      @source_dir = File.join(@tmpdir, 'source')
      FileUtils.mkdir_p(@source_dir)

      @target_dir = File.join(@tmpdir, 'target')
      FileUtils.mkdir_p(@target_dir)
    end

    after(:each) do
      FileUtils.remove_entry_secure(@tmpdir)
    end

    context 'source does not exist' do
      it 'fails when the source dir does not exist' do
        resource = Puppet::Type.type(:pki_cert_sync).new({
          :name         => @target_dir,
          :source       => '/does/not/exist/source',
          :provider     => 'redhat'
        })
        provider = resource.provider

        msg = "'/does/not/exist/source' is not a valid directory"
        expect { provider.source }.to raise_error(/#{Regexp.escape(msg)}/)
      end
    end

    context 'target is out of sync' do
      let(:provider) { resource.provider }
      let(:resource) do
        Puppet::Type.type(:pki_cert_sync).new({
          :name         => @target_dir,
          :source       => @source_dir,
          :provider     => 'redhat'
        })
      end

      let(:cacerts_file) { File.join(@target_dir, 'cacerts_file') }
      let(:cacerts_dot_file) { File.join(@target_dir, '.cacerts_file') }
      let(:cacerts_no_hdrs_file) { File.join(@target_dir, 'cacerts_no_headers.pem') }
      let(:cacerts_no_hdrs_dot_file) { File.join(@target_dir, '.cacerts_no_headers.pem') }

      context 'target does not exist' do
        it 'should create and populate the target dir' do
          # each entry has 4 fields
          # - fully qualified path to the test file
          # - relative path of where the file will be place in the test
          # - alternate name to use for the test file, when set
          # - the certificate subject hash for the file, when set
          cert_info = [
            [ cert1_file,            ''    , nil,         cert_subj_hash[:cert1]],
            [ cert2_file,            'd2'  , nil,         cert_subj_hash[:cert2]],
            [ cert3_no_hdrs_file, 'd3a/d3b', 'cert3.pem', cert_subj_hash[:cert3]],
          ]
          populate_cert_dir(@source_dir, cert_info)

          its = provider.source
          expected_its = {
            'cert1.pem'              => '4a44b594.0',
            'd2/cert2.pem'           => 'ae3116e1.0',
            'd3a/d3b/cert3.pem'      => 'db039224.0',
            'cacerts.pem'            => 'cacerts.pem',
            'cacerts_no_headers.pem' => 'cacerts_no_headers.pem'
          }
          expect( its ).to eq expected_its

          expect( provider.source_insync?(its, @target_dir) ).to eq false
          provider.source = @target_dir

=begin
          validate_cert_dir(@target_dir, cert_info)
=end
          

puts `find #{@target_dir}`
puts `ls -l #{@target_dir}`
        end
      end

      context 'target is missing a directory' do
      end

      context 'target is missing a certificate file' do
        ['cert', 'cacerts.pem', 'cacerts_no_headers.pem'].each do |cert_file|
        end
      end

      context 'target is missing a link to a certificate file' do
      end

      context 'target has a certificate file with differing content' do
        ['cert', 'cacerts.pem', 'cacerts_no_headers.pem'].each do |cert_file|
        end
      end

      context 'target has an extra directory and purge is enabled' do
      end

      context 'target has an extra certificate file and purge is enabled' do
      end
    end

    context 'target is in sync' do
      context 'target matches source' do
      end

      context 'target has an extra directory and purge is disabled' do
      end

      context 'target has an extra certificate file and purge is disabled' do
      end
    end

    context 'source contains no valid certificate files' do
    end

    context 'source contains non-certificate files' do
    end

    context 'source contains different certificate files with same subject hash' do
      it 'should create a unique link for each matching input' do
          cert_files = [
            [ cert1_file,            ''],
            [ cert1_file,            'dir1'],
            [ cert1_no_hdrs_file, 'dir1'],
            [ cert2_file,            'dir2'],
            [ cert3_no_hdrs_file, 'dir3a/dir3b']
          ]
          populate_cert_dir(@source_dir, cert_files)
      end
    end

    context 'file list in source changes between the source() and source_insync?() calls' do
    end

    context 'file list in source changes between the source() and source=() calls' do
    end
  end
end
