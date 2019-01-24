require 'spec_helper'
require 'tmpdir'

provider_class = Puppet::Type.type(:pki_cert_sync).provider(:redhat)

describe provider_class do
  let(:files_dir) { File.join(File.dirname(__FILE__), 'files') }
  let(:cert1_file) { File.join(files_dir, 'cert1.pem') }
  let(:cert1_no_headers_file) { File.join(files_dir, 'cert1_no_headers.pem') }
  let(:cert2_file) { File.join(files_dir, 'cert2.pem') }
  let(:cert3_file) { File.join(files_dir, 'cert3.pem') }
  let(:cacerts_file) { File.join(files_dir, 'cacerts.pem') }
  let(:cacerts_no_headers_file) { File.join(files_dir, 'cacerts_no_headers.pem') }

  # Test methods that do not rely upon internal provider state
  context 'stateless methods' do
    before(:all) do
      @tmpdir = Dir.mktmpdir
      @source_dir = File.join(@tmpdir, 'source')
      FileUtils.mkdir_p(@source_dir)

      @target_dir = File.join(@tmpdir, 'target')
      FileUtils.mkdir_p(@target_dir)
    end

    after(:all) { FileUtils.remove_entry_secure @tmpdir }

    let(:provider) { resource.provider }
    let(:resource) do
      Puppet::Type.type(:pki_cert_sync).new({
        :name         => @target_dir,
        :source       => @source_dir,
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
        expected = IO.read(cert1_no_headers_file)
        expect( provider.strip_x509_headers(IO.read(cert1_file)) ).to eq expected
      end

      it 'strips headers from multiple certificates' do
        expected = IO.read(cacerts_no_headers_file)
        expect( provider.strip_x509_headers(IO.read(cacerts_file)) ).to eq expected
      end

      it 'retains the content of a single certificate when no headers exist' do
        expected = IO.read(cert1_no_headers_file)
        expect( provider.strip_x509_headers(IO.read(cert1_no_headers_file)) ).to eq expected
      end

      it 'retains the content of multiple certificates when no headers exist' do
        expected = IO.read(cacerts_no_headers_file)
        expect( provider.strip_x509_headers(IO.read(cacerts_no_headers_file)) ).to eq expected
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

    context 'source does not exist' do
    end

    context 'target is out of sync' do
      context 'target does not exist' do
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
    end

    context 'file list in source changes between the source() and source_insync?() calls' do
    end

    context 'file list in source changes between the source() and source=() calls' do
    end
  end
end
