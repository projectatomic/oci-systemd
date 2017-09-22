%global provider        github
%global provider_tld    com
%global project         projectatomic
%global repo            oci-systemd-hook
# https://github.com/projectatomic/oci-register-machine
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
%global commit          de345df3c18a6abfc8d9cf3822405c0e1bbe65c9
%global shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:           oci-systemd-hook
Version:        0.1.5
Release:        1.git%{shortcommit}%{?dist}
Summary:        OCI systemd hook for docker
Group:          Applications/Text
License:        GPLv3+
URL:            https://%{provider_prefix}
Source0:        https://%{provider_prefix}/archive/%{commit}/%{repo}-%{shortcommit}.tar.gz

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  pkgconfig(yajl)
BuildRequires:  pkgconfig(libselinux)
BuildRequires:  pkgconfig(mount)
BuildRequires:  golang-github-cpuguy83-go-md2man

%description
OCI systemd hooks enable running systemd in a OCI runc/docker container.

%prep
%setup -q -n %{repo}-%{commit}

%build
autoreconf -i
%configure --libexecdir=/usr/libexec/oci/hooks.d/
make %{?_smp_mflags}

%install
%make_install

#define license tag if not already defined
%{!?_licensedir:%global license %doc}
%files
%{_libexecdir}/oci/hooks.d/oci-systemd-hook
%{_mandir}/man1/oci-systemd-hook.1*
%doc README.md
%license LICENSE
%dir /%{_libexecdir}/oci
%dir /%{_libexecdir}/oci/hooks.d
%dir %{_usr}/share/containers/oci/hooks.d
%{_usr}/share/containers/oci/hooks.d/oci-register-machine.json

%changelog
* Wed Sep 13 2017 Dan Walsh <dwalsh@redhat.com> - 0.1.5-1.gitde345df
- Add support for json configuration to identify when to use hook
- Needed for crio package

* Thu Feb 18 2016 Dan Walsh <dwalsh@redhat.com> - 0.1.4-1.gitde345df
- Fix up to prepare for review

* Mon Nov 23 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.3
- Fix bug in man page installation
* Mon Nov 23 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.2
- Add man pages
* Mon Nov 23 2015 Mrunal Patel <mrunalp@gmail.com> - 0.1.1
- Initial RPM release
