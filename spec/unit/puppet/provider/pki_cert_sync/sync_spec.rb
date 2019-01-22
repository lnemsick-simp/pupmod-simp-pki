require 'spec_helper'
require 'json'
require 'yaml'
require 'facter'

describe 'Puppet::Type.type(:tpm2_ownership).provider(:tpm2tools)' do

  let(:all_clear) {
    YAML.safe_load(File.read(File.expand_path('spec/files/tpm2/mocks/tpm2_getcap_-c_properties-variable/clear-clear-clear.yaml')))
  }

  let(:all_set) {
    YAML.safe_load(File.read(File.expand_path('spec/files/tpm2/mocks/tpm2_getcap_-c_properties-variable/set-set-set.yaml')))
  }

  let(:mixed) {
    YAML.safe_load(File.read(File.expand_path('spec/files/tpm2/mocks/tpm2_getcap_-c_properties-variable/set-set-clear.yaml')))
  }
  let (:expected_hash1) {{
    :owner            => :clear,
    :endorsement      => :clear,
    :lockout          => :clear,
    'reserved1'       => :clear,
    'disableClear'    => :clear,
    'inLockout'       => :clear,
    'tpmGeneratedEPS' => :set,
    'reserved2'       => :clear,
  }}


  let (:provider) { resource.provider }
  let (:resource) {
    Puppet::Type.type(:tpm2_ownership).new({
    :name         => 'tpm2',
    :owner        => 'clear',
    :lockout      => 'clear',
    :endorsement  => 'clear',
    :provider     => 'tpm2tools'
    })}

  describe 'get_password_options' do
    context 'first set' do
      let (:resource) {
        Puppet::Type.type(:tpm2_ownership).new({
        :name             => 'tpm2',
        :owner_auth       => 'ownerpassword',
        :lockout_auth     => 'lockpassword',
        :endorsement_auth => 'endorsepassword',
        :owner            => 'set',
        :lockout          => 'set',
        :endorsement      => 'clear',
        :provider         => 'tpm2tools'
        })}

      let (:current1) {{
        :owner       => :clear,
        :endorsement => :clear,
        :lockout     => :clear,
      }}
      it 'should return lower case options for all but endorsement' do
        allow(Facter).to receive(:value).with(:kernel).and_return(:Linux)
        provider = resource.provider
        passwd_args = provider.get_passwd_options(current1,resource)
        expect(passwd_args).to eq(['-o','ownerpassword','-l','lockpassword'])
      end
    end
    context 'second set' do
      # If current = set and desired = set then you must clear it and set it, hence ['-O','ownerpassword','-o','ownerpassword']
      # If current = clear and desired = set then you need to set it, hence ['-e','endorsepassword']
      # if current = set and desired = clear then you need to clear it, hence ['-L','lockpassword']
      let (:resource) {
        Puppet::Type.type(:tpm2_ownership).new({
        :name             => 'tpm2',
        :owner_auth       => 'ownerpassword',
        :lockout_auth     => 'lockpassword',
        :endorsement_auth => 'endorsepassword',
        :owner            => 'set',
        :lockout          => 'clear',
        :endorsement      => 'set',
        :in_hex           => 'true',
        :provider         => 'tpm2tools'
        })}

      let (:current2) {{
        :owner       => :set,
        :endorsement => :clear,
        :lockout     => :set,
      }}
      it 'should return set for all passwords' do
        allow(Facter).to receive(:value).with(:kernel).and_return(:Linux)
        provider = resource.provider
        passwd_args = provider.get_passwd_options(current2,resource)
        expect(passwd_args).to eq(['-O','ownerpassword','-o','ownerpassword','-e','endorsepassword','-L','lockpassword', '-X'])
      end
    end
    context 'clear when lockout password is not set' do
      let (:resource) {
        Puppet::Type.type(:tpm2_ownership).new({
        :name             => 'tpm2',
        :owner_auth       => 'ownerpassword',
        :lockout_auth     => 'lockpassword',
        :endorsement_auth => 'endorsepassword',
        :owner            => 'clear',
        :lockout          => 'clear',
        :endorsement      => 'clear',
        :provider         => 'tpm2tools'
      })}

      let (:current) {{
        :owner       => :set,
        :endorsement => :set,
        :lockout     => :clear,
      }}
      it 'should return not contain -L or -l options' do
        allow(Facter).to receive(:value).with(:kernel).and_return(:Linux)
        provider = resource.provider
        passwd_args = provider.get_passwd_options(current,resource)
        expect(passwd_args).to eq(['-O', 'ownerpassword','-E','endorsepassword'])
      end
    end
  end
end
