# This Defined Type provides a useful copy function for properly copying the
# entire set of SIMP-based PKI certificates as deployed by the PKI module to a
# different location.
#
# This is particularly important when dealing with SELinux enabled services
# since they tend to react poorly to symlinks.
#
# @param pki
#
#   * If set to ``simp`` or ``true``
#     * Certificates will be centralized in /etc/pki/simp_apps/, and copied to
#       ``/etc/pki/simp_apps/$name/x509``.
#
#   * If set to ``simp``
#     * Include the ``pki`` class
#
#   * If set to ``false``
#     * Certificates will *not* be centralized, and you must provide a ``$destination``
#
# @param name [Variant[String,Stdlib::Absolutepath]]
#
#   * If ``$pki = true`` or ``$pki = 'simp'`` this parameter will be used to namespace
#     certificates in ``/etc/pki/simp_apps/$name/x509``.
#
#   * If ``$pki = false``, this variable has no effect.
#
# @param source
#   Where to find the certificates. This value could be one of a few types:
#     * Absolute path
#     * A file URL in the form of ``(https|puppet):///file/path``. See the ``file``
#       resource documentation for details on the format of this URL
#     * An NSS database. This must be managed by something else, like IPA.
#
#   If the setting is a path (file or URL), the locations referenced must have
#   the following structure:
#     * ``<path>/cacerts``
#     * ``<path>/private``
#     * ``<path>/public``
#
#     * **NOTE:** No other directories will be copied!
#
# @param destination
#   Optional. The destination that PKI certs get copied to.
#
#     * If ``$pki = false``:
#       * You *must* specify $destination.
#       * You will need to ensure that all parent directories have been
#         properly created.
#       * A 'pki' directory will be created under this space
#         * For example, if you set this to ``/foo/bar`` then ``/foo/bar/pki``
#           will be created
#
#     * If ``$pki = true`` or ``$pki = 'simp'``:
#       * This variable has no effect.
#
# @param owner
#   The owner of the directories/files that get copied
#
# @param group
#   The group of the directories/files that get copied
#
# @param strip_cacerts_headers
#   Whether to strip the X509 certificate headers from the
#   `$source/cacerts/cacerts.pem` file.  Only applies when that
#   file already exists.  Useful for applications that are unable
#   to handle those headers.
#
# @author https://github.com/simp/pupmod-simp-pki/graphs/contributors
#
define pki::copy (
  Variant[Boolean,Enum['simp']]  $pki                   = simplib::lookup('simp_options::pki', { 'default_value' => false}),
  String                         $source                = simplib::lookup('simp_options::pki::source', { 'default_value' => '/etc/pki/simp/x509' }),
  Optional[Stdlib::Absolutepath] $destination           = undef,
  String                         $owner                 = 'root',
  String                         $group                 = 'root',
  Boolean                        $strip_cacerts_headers = false,
) {

  include '::pki::copy::apps_dir'

  if !$pki {
    if !$destination {
      fail('You must specify a $destination if $pki false.')
    }
    else {
      $_destination = "${destination}/pki"

      file { $_destination:
        ensure => 'directory',
        owner  => $owner,
        group  => $group,
        mode   => '0640',
      }
    }
  }
  else {
    if $destination {
      notify { "pki_copy_${name}":
        message => "Pki is managing cert destination. Ignoring specified destination ${destination}"
      }
    }

    $_destination = "${pki::copy::apps_dir::target}/${name}/x509"

    file { "${pki::copy::apps_dir::target}/${name}":
      ensure => 'directory',
      owner  => $owner,
      group  => $group,
      mode   => '0640'
    }

    file { $_destination:
      ensure => 'directory',
      owner  => $owner,
      group  => $group,
      mode   => '0640'
    }

    if $pki == 'simp' {
      include '::pki'
      Class['pki'] -> Pki::Copy[$name]
    }
  }

  file { "${_destination}/public":
    ensure    => 'directory',
    owner     => $owner,
    group     => $group,
    mode      => '0640',
    recurse   => true,
    source    => "${source}/public",
    seltype   => 'cert_t',
    show_diff => false
  }

  file { "${_destination}/private":
    ensure    => 'directory',
    owner     => $owner,
    group     => $group,
    mode      => '0640',
    recurse   => true,
    source    => "${source}/private",
    seltype   => 'cert_t',
    show_diff => false
  }

  if $strip_cacerts_header  {
    # This block will copy over the contents of the source directory to
    # the destination and, if a ${_destination}/cacerts/cacerts.pem file
    # exists, strip the headers from it. Existing files/directories
    # uniquely found in the destination are preserved.

    file { "${_destination}/cacerts":
      ensure    => 'directory',
      owner     => $owner,
      group     => $group,
      mode      => '0640',
      recurse   => true,
      seltype   => 'cert_t',
      show_diff => false
    }

#FIXME? pass in group, owner, mode, selinux context
    pki_cert_sync { "${_destination}/cacerts":
      source                => "${source}/cacerts",
      purge                 => false,
      generate_cacerts_file => false,
      strip_cacerts_headers => true
    }
  }
  else {
    # Simple (fast) sync. Certs in source are assumed to be properly set
    # up. Existing files/directories uniquely found in the destination
    # are preserved.
    file { "${_destination}/cacerts":
      ensure    => 'directory',
      owner     => $owner,
      group     => $group,
      mode      => '0640',
      recurse   => true,
      source    => "${source}/cacerts",
      seltype   => 'cert_t',
      show_diff => false
    }
  }
}
