oci-systemd-hook(1) -- OCI systemd hook
=============================================

## SYNOPSIS

`oci-systemd-hook` prestart [container.json]

`oci-systemd-hook` poststop

## DESCRIPTION

Setup environment for systemd to run in docker or a OCI compatible runtime.
It is expected to receive the state of the container including the pid and ID over stdin
as defined in the OCI specification (https://github.com/opencontainers/specs).
It mounts tmpfs at /run and /tmp, links journal directory to the host using a bind mount
and creates /etc/machine-id for the container systemd.

## ARGUMENTS

  * `prestart`:  Setup the systemd environment in a container

  * `container.json`: file which describes the container. oci-systemd-hook will examine the json data for the `CMD` option and only setup the environment if the CMD is `init` or `systemd`. Only available on `prestart`.
  
  * `poststop`:  Teardown and undo the changes on the host done during prestart


## AUTHORS
Mrunal Patel <mrunalp@gmail.com>
Dan Walsh <dwalsh@redhat.com>
