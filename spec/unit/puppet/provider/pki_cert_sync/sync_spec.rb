require 'spec_helper'
require 'tmpdir'

provider_class = Puppet::Type.type(:pki_cert_sync).provider(:redhat)

describe provider_class do
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

    let (:provider) { resource.provider }
    let (:resource) do
      Puppet::Type.type(:pki_cert_sync).new({
        :name         => @target_dir,
        :source       => @source_dir,
        :provider     => 'redhat'
      })
    end

    describe 'file_diff' do
    end

    descripte 'generate_cacerts_pem' do

    describe 'strip_x509_headers' do
    end

  end

  # Test provider overall operation in order to exercise the logic in
  # the remaining methods.  This testing approach is required because
  # the source() method generates state and stores it in provider
  # instance variables.
  context 'stateful methods via scenarios' do

    context 'source does not exist' do
    end

    context 'target is out of sync' do
      context 'target does not exist' do
      end

      context 'target is missing a directory' do
      end

      context 'target is missing a certificate file' do
      end

=begin
      context 'target is missing a link to a certificate file' do
      end
=end

      context 'target has a certificate file with differing content' do
      end

      context 'target has an extra directory and purge is enabled' do
      end

      context 'target has an extra certificate file and purge is enabled' do
      end

      context 'target cacerts.pem has X.509 headers and strip_cacerts_headers is now enabled' do
      end

      context 'target cacerts.pem was stripped of X.509 headers and strip_cacerts_headers is now disabled' do
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
