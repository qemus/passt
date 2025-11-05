# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# Copyright (c) 2022 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

%global git_hash {{{ git_head }}}
%global selinuxtype targeted
%global selinux_policy_version 41.41

Name:		passt
Version:	{{{ git_version }}}
Release:	1%{?dist}
Summary:	User-mode networking daemons for virtual machines and namespaces
License:	GPL-2.0-or-later AND BSD-3-Clause
Group:		System Environment/Daemons
URL:		https://passt.top/
Source:		https://passt.top/passt/snapshot/passt-%{git_hash}.tar.xz

BuildRequires:	gcc, make, checkpolicy, selinux-policy-devel
Requires:	(%{name}-selinux = %{version}-%{release} if selinux-policy-%{selinuxtype})

%description
passt implements a translation layer between a Layer-2 network interface and
native Layer-4 sockets (TCP, UDP, ICMP/ICMPv6 echo) on a host. It doesn't
require any capabilities or privileges, and it can be used as a simple
replacement for Slirp.

pasta (same binary as passt, different command) offers equivalent functionality,
for network namespaces: traffic is forwarded using a tap interface inside the
namespace, without the need to create further interfaces on the host, hence not
requiring any capabilities or privileges.

%package		selinux
BuildArch:		noarch
Summary:		SELinux support for passt and pasta
Requires:		selinux-policy-%{selinuxtype}
Requires:		container-selinux
Requires(post):		selinux-policy-%{selinuxtype}
Requires(post):		container-selinux
Requires(post):		policycoreutils
Requires(post):		libselinux-utils
Requires(preun):	policycoreutils
BuildRequires:		selinux-policy-devel
BuildRequires:		pkgconfig(systemd)
Recommends:		selinux-policy-%{selinuxtype} >= %{selinux_policy_version}

%description selinux
This package adds SELinux enforcement to passt(1), pasta(1), passt-repair(1).

%prep
%setup -q -n passt-%{git_hash}

%build
%set_build_flags
# The Makefile creates symbolic links for pasta, but we need actual copies for
# SELinux file contexts to work as intended. Same with pasta.avx2 if present.
# Build twice, changing the version string, to avoid duplicate Build-IDs.
%make_build VERSION="%{version}-%{release}.%{_arch}-pasta"
mv -f passt pasta
%ifarch x86_64
mv -f passt.avx2 pasta.avx2
%make_build passt passt.avx2 VERSION="%{version}-%{release}.%{_arch}"
%else
%make_build passt VERSION="%{version}-%{release}.%{_arch}"
%endif

%install
# Already built (not as symbolic links), see above
touch pasta
%ifarch x86_64
touch pasta.avx2
%endif

%make_install DESTDIR=%{buildroot} prefix=%{_prefix} bindir=%{_bindir} mandir=%{_mandir} docdir=%{_docdir}/%{name}
%ifarch x86_64
ln -sr %{buildroot}%{_mandir}/man1/passt.1 %{buildroot}%{_mandir}/man1/passt.avx2.1
ln -sr %{buildroot}%{_mandir}/man1/pasta.1 %{buildroot}%{_mandir}/man1/pasta.avx2.1
install -p -m 755 %{buildroot}%{_bindir}/passt.avx2 %{buildroot}%{_bindir}/pasta.avx2
%endif

pushd contrib/selinux
make -f %{_datadir}/selinux/devel/Makefile
install -p -m 644 -D passt.pp %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/passt.pp
install -p -m 644 -D passt.if %{buildroot}%{_datadir}/selinux/devel/include/distributed/passt.if
install -p -m 644 -D pasta.pp %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/pasta.pp
install -p -m 644 -D passt-repair.pp %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/passt-repair.pp
popd

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/passt.pp %{_datadir}/selinux/packages/%{selinuxtype}/pasta.pp %{_datadir}/selinux/packages/%{selinuxtype}/passt-repair.pp

%postun selinux
if [ $1 -eq 0 ]; then
	%selinux_modules_uninstall -s %{selinuxtype} passt pasta passt-repair
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

%files
%license LICENSES/{GPL-2.0-or-later.txt,BSD-3-Clause.txt}
%dir %{_docdir}/%{name}
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/demo.sh
%{_bindir}/passt
%{_bindir}/pasta
%{_bindir}/qrap
%{_bindir}/passt-repair
%{_mandir}/man1/passt.1*
%{_mandir}/man1/pasta.1*
%{_mandir}/man1/qrap.1*
%{_mandir}/man1/passt-repair.1*
%ifarch x86_64
%{_bindir}/passt.avx2
%{_mandir}/man1/passt.avx2.1*
%{_bindir}/pasta.avx2
%{_mandir}/man1/pasta.avx2.1*
%endif

%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/passt.pp
%{_datadir}/selinux/devel/include/distributed/passt.if
%{_datadir}/selinux/packages/%{selinuxtype}/pasta.pp
%{_datadir}/selinux/packages/%{selinuxtype}/passt-repair.pp

%changelog
{{{ passt_git_changelog }}}
