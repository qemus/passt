# passt: Plug A Simple Socket Transport

_passt_ implements a translation layer between a Layer-2 network interface and
native Layer-4 sockets (TCP, UDP, ICMP/ICMPv6 echo) on a host. It doesn't
require any capabilities or privileges, and it can be used as a simple
replacement for Slirp.

# pasta: Pack A Subtle Tap Abstraction

_pasta_ (same binary as _passt_, different command) offers equivalent
functionality, for network namespaces: traffic is forwarded using a tap
interface inside the namespace, without the need to create further interfaces on
the host, hence not requiring any capabilities or privileges.

It also implements a tap bypass path for local connections: packets with a local
destination address are moved directly between Layer-4 sockets, avoiding Layer-2
translations, using the _splice_(2) and _recvmmsg_(2)/_sendmmsg_(2) system calls
for TCP and UDP, respectively.

- [Motivation](#motivation)
- [Features](#features)
- [Interfaces and Environment](#interfaces-and-environment)
- [Services](#services)
- [Addresses](#addresses)
- [Protocols](#protocols)
- [Ports](#ports)
- [Demo](#demo)
- [Continuous Integration](#continuous-integration)
- [Performance](#performance_1)
- [Try it](#try-it)
- [Contribute](#contribute)
- [Security and Vulnerability Reports](#security-and-vulnerability-reports)

See also the [man page](/builds/latest/web/passt.1.html).

## Motivation

### passt

When container workloads are moved to virtual machines, the network traffic is
typically forwarded by interfaces operating at data link level. Some components
in the containers ecosystem (such as _service meshes_), however, expect
applications to run locally, with visible sockets and processes, for the
purposes of socket redirection, monitoring, port mapping.

To solve this issue, user mode networking, as provided e.g. by _libslirp_,
can be used. Existing solutions implement a full TCP/IP stack, replaying traffic
on sockets that are local to the pod of the service mesh. This creates the
illusion of application processes running on the same host, eventually separated
by user namespaces.

While being almost transparent to the service mesh infrastructure, that kind of
solution comes with a number of downsides:

* three different TCP/IP stacks (guest, adaptation and host) need to be
  traversed for every service request
* addressing needs to be coordinated to create the pretense of consistent
  addresses and routes between guest and host environments. This typically needs
  a NAT with masquerading, or some form of packet bridging
* the traffic seen by the service mesh and observable externally is a distant
  replica of the packets forwarded to and from the guest environment:
  * TCP congestion windows and network buffering mechanisms in general operate
    differently from what would be naturally expected by the application
  * protocols carrying addressing information might pose additional challenges,
    as the applications don't see the same set of addresses and routes as they
    would if deployed with regular containers

_passt_ implements a thinner layer between guest and host, that only implements
what's strictly needed to pretend processes are running locally. The TCP
adaptation doesn't keep per-connection packet buffers, and reflects observed
sending windows and acknowledgements between the two sides. This TCP adaptation
is needed as _passt_ runs without the `CAP_NET_RAW` capability: it can't create
raw IP sockets on the pod, and therefore needs to map packets at Layer-2 to
Layer-4 sockets offered by the host kernel.

See also a
[detailed illustration](https://gitlab.com/abologna/kubevirt-and-kvm/-/blob/master/Networking.md)
of the problem and what lead to this approach.

### pasta

On Linux, regular users can create network namespaces and run application
services inside them. However, connecting namespaces to other namespaces and to
external hosts requires the creation of network interfaces, such as `veth`
pairs, which needs in turn elevated privileges or the `CAP_NET_ADMIN`
capability. _pasta_, similarly to _slirp4netns_, solves this problem by creating
a tap interface available to processes in the namespace, and mapping network
traffic outside the namespace using native Layer-4 sockets.

Existing approaches typically implement a full, generic TCP/IP stack for this
translation between data and transport layers, without the possibility of
speeding up local connections, and usually requiring NAT. _pasta_:

* avoids the need for a generic, full-fledged TCP/IP stack by coordinating TCP
  connection dynamics between sender and receiver
* offers a fast bypass path for local connections: if a process connects to
  another process on the same host across namespaces, data is directly forwarded
  using pairs of Layer-4 sockets
* with default options, maps routing and addressing information to the
  namespace, avoiding any need for NAT

## Features

✅: done/supported, ❌: out of scope, 🛠: in progress/being considered
⌚: nice-to-have, eventually

### Protocols
* ✅ IPv4
    * ✅ all features, except for
    * ❌ fragmentation
* ✅ IPv6
    * ✅ all features, except for
    * ❌ fragmentation
    * ❌ jumbograms
* ✅ [TCP](/passt/tree/tcp.c)
    * ✅ Window Scaling (RFC 7323)
    * ✅ Defenses against Sequence Number Attacks (RFC 6528)
    * ⌚ [Protection Against Wrapped Sequences](https://bugs.passt.top/show_bug.cgi?id=1) (PAWS, RFC 7323)
    * ⌚ [Timestamps](https://bugs.passt.top/show_bug.cgi?id=1) (RFC 7323)
    * ❌ Selective Acknowledgment (RFC 2018)
* ✅ [UDP](/passt/tree/udp.c)
* ✅ ICMP/ICMPv6 Echo
* ⌚ [IGMP/MLD](https://bugs.passt.top/show_bug.cgi?id=2) proxy
* ⌚ [SCTP](https://bugs.passt.top/show_bug.cgi?id=3)

### Portability
* Linux
    * ✅ starting from 4.18 kernel version
    * ✅ starting from 3.13 kernel version
* ✅ run-time selection of AVX2 build
* C libraries:
    * ✅ glibc
    * ✅ [_musl_](https://bugs.passt.top/show_bug.cgi?id=4)
    * ⌚ [_uClibc-ng_](https://bugs.passt.top/show_bug.cgi?id=5)
* ⌚ [FreeBSD](https://bugs.passt.top/show_bug.cgi?id=6),
  [Darwin](https://bugs.passt.top/show_bug.cgi?id=6)
* ⌚ [NetBSD](https://bugs.passt.top/show_bug.cgi?id=7),
  [OpenBSD](https://bugs.passt.top/show_bug.cgi?id=7)
* ⌚ [Win2k](https://bugs.passt.top/show_bug.cgi?id=8)

### Security
* ✅ no dynamic memory allocation (`sbrk`(2), `brk`(2), `mmap`(2) [blocked via
  `seccomp`](/passt/tree/seccomp.sh))
* ✅ root operation not allowed outside user namespaces
* ✅ all capabilities dropped, other than `CAP_NET_BIND_SERVICE` (if granted)
* ✅ with default options, user, mount, IPC, UTS, PID namespaces are detached
* ✅ no external dependencies (other than a standard C library)
* ✅ restrictive seccomp profiles (33 syscalls allowed for _passt_, 43 for
  _pasta_ on x86_64)
* ✅ examples of [AppArmor](/passt/tree/contrib/apparmor) and
  [SELinux](/passt/tree/contrib/selinux) profiles available
* ✅ static checkers in continuous integration (clang-tidy, cppcheck)
* ✅️ clearly defined boundary-checked packet abstraction
* 🛠️ ~5 000 LoC target
* ⌚ [fuzzing](https://bugs.passt.top/show_bug.cgi?id=9), _packetdrill_ tests
* ⌚ stricter [synflood protection](https://bugs.passt.top/show_bug.cgi?id=10)
* 💡 [add](https://lists.passt.top/) [your](https://bugs.passt.top/)
  [ideas](https://chat.passt.top)

### Configurability
* ✅ all addresses, ports, port ranges
* ✅ optional NAT, not required
* ✅ all protocols
* ✅ _pasta_: auto-detection of bound ports
* ⌚ run-time configuration of port ranges without autodetection
* ⌚ configuration of port ranges for autodetection
* 💡 [add](https://lists.passt.top/) [your](https://bugs.passt.top/)
  [ideas](https://chat.passt.top)

### Performance
* ✅ maximum two (cache hot) copies on every data path
* ✅ _pasta_: zero-copy for local connections by design (no configuration
  needed)
* ✅ generalised coalescing and batching on every path for every supported
  protocol
* ✅ 4 to 50 times IPv4 TCP throughput of existing, conceptually similar
  solutions depending on MTU (UDP and IPv6 hard to compare)
* ✅ [_vhost-user_ support](https://bugs.passt.top/show_bug.cgi?id=25) for
  maximum one copy on every data path and lower request-response latency
* ⌚ [multithreading](https://bugs.passt.top/show_bug.cgi?id=13)
* ⌚ [raw IP socket support](https://bugs.passt.top/show_bug.cgi?id=14) if
  `CAP_NET_RAW` is granted
* ⌚ eBPF support (might not improve performance over vhost-user)

### Interfaces
* ✅ native [qemu](https://bugs.passt.top/show_bug.cgi?id=11) support (_passt_)
* ✅ native [libvirt](https://bugs.passt.top/show_bug.cgi?id=12) support
  (_passt_)
* ✅ Podman [integration](https://github.com/containers/podman/pull/16141)
  (_pasta_)
* ✅ bug-to-bug compatible
  [_slirp4netns_ replacement](/passt/tree/slirp4netns.sh)
* ✅ out-of-tree patch for
  [Kata Containers](/passt/tree/contrib/kata-containers) available
* ✅ rootless Docker
  [network back-end](https://docs.docker.com/engine/security/rootless/#networking-errors)
  via moby/rootlesskit

### Availability
* official packages for:
    * ✅ [Alpine Linux](https://pkgs.alpinelinux.org/packages?name=passt)
    * ✅ [Arch Linux](https://archlinux.org/packages/extra/x86_64/passt/) ([aarch64](https://archlinuxarm.org/packages/aarch64/passt), [i486](https://www.archlinux32.org/packages/?q=passt))
    * ✅ [CentOS Stream](https://gitlab.com/redhat/centos-stream/rpms/passt)
    * ✅ [Debian](https://tracker.debian.org/pkg/passt)
    * ✅ [Fedora](https://src.fedoraproject.org/rpms/passt)
    * ✅ [Gentoo](https://packages.gentoo.org/packages/net-misc/passt)
    * ✅ [GNU Guix](https://packages.guix.gnu.org/packages/passt/)
    * ✅ [OpenSUSE](https://build.opensuse.org/package/requests/Virtualization:containers/passt)
    * ✅ [Ubuntu](https://launchpad.net/ubuntu/+source/passt)
    * ✅ [Void Linux](https://voidlinux.org/packages/?q=passt)
* unofficial packages for:
    * ✅ [EPEL, Mageia](https://copr.fedorainfracloud.org/coprs/sbrivio/passt/)
* ✅ unofficial [packages](https://passt.top/builds/latest/x86_64/) from x86_64
  static builds for other RPM-based distributions
* ✅ unofficial [packages](https://passt.top/builds/latest/x86_64/) from x86_64
  static builds for other Debian-based distributions
* ✅ testing on non-x86_64 architectures (aarch64, armv7l, i386, ppc64, ppc64le,
  s390x)

### Services
* ✅ built-in [ARP proxy](/passt/tree/arp.c)
* ✅ minimalistic [DHCP server](/passt/tree/dhcp.c)
* ✅ minimalistic [NDP proxy](/passt/tree/ndp.c) with router advertisements and
  SLAAC support
* ✅ minimalistic [DHCPv6 server](/passt/tree/dhcpv6.c)
* ⌚ fine-grained configurability of DHCP, NDP, DHCPv6 options

## Interfaces and Environment

_passt_ exchanges packets with _qemu_ via UNIX domain socket, using the `socket`
back-end in qemu. This is supported since qemu 7.2.

For older versions, the [qrap](/passt/tree/qrap.c) wrapper can be used to
connect to a UNIX domain socket and to start qemu, which can now use the file
descriptor that's already opened.

This approach, compared to using a _tap_ device, doesn't require any security
capabilities, as we don't need to create any interface.

_pasta_ runs out of the box with any recent (post-3.8) Linux kernel.

## Services

_passt_ and _pasta_ provide some minimalistic implementations of networking
services:

* [ARP proxy](/passt/tree/arp.c), that resolves the address of
  the host (which is used as gateway) to the original MAC address of the host
* [DHCP server](/passt/tree/dhcp.c), a simple implementation
  handing out one single IPv4 address to the guest or namespace, namely, the
  same address as the first one configured for the upstream host interface, and
  passing the nameservers configured on the host
* [NDP proxy](/passt/tree/ndp.c), which can also assign prefix
  and nameserver using SLAAC
* [DHCPv6 server](/passt/tree/dhcpv6.c): a simple
  implementation handing out one single IPv6 address to the guest or namespace,
  namely, the same address as the first one configured for the upstream host
  interface, and passing the nameservers configured on the host

## Addresses

For IPv4, the guest or namespace is assigned, via DHCP, the same address as the
upstream interface of the host, and the same default gateway as the default
gateway of the host. Addresses are translated in case the guest is seen using a
different address from the assigned one.

For IPv6, the guest or namespace is assigned, via SLAAC, a prefix derived from
the address of the upstream interface of the host, the same default route as the
default route of the host, and, if a DHCPv6 client is running in the guest or
namespace, also the same address as the upstream address of the host. This means
that, with a DHCPv6 client in the guest or namespace, addresses don't need to be
translated. Should the client use a different address, the destination address
is translated for packets going to the guest or to the namespace.

### Local connections with _passt_

For UDP and TCP, for both IPv4 and IPv6, packets from the host addressed to a
loopback address are forwarded to the guest with their source address changed to
the address of the gateway or first hop of the default route. This mapping is
reversed on the other way.

### Local connections with _pasta_

Packets addressed to a loopback address in either namespace are directly
forwarded to the corresponding (or configured) port in the other namespace.
Similarly as _passt_, packets from the non-init namespace addressed to the
default gateway, which are therefore sent via the tap device, will have their
destination address translated to the loopback address.

## Protocols

_passt_ and _pasta_ support TCP, UDP and ICMP/ICMPv6 echo (requests and
replies). More details about the TCP implementation are described in the
[theory of operation](/passt/tree/tcp.c), and similarly for
[UDP](/passt/tree/udp.c).

An IGMP/MLD proxy is currently work in progress.

## Ports

### passt

To avoid the need for explicit port mapping configuration, _passt_ can bind to
all unbound non-ephemeral (0-49152) TCP and UDP ports. Binding to low ports
(0-1023) will fail without additional capabilities, and ports already bound
(service proxies, etc.) will also not be used. Smaller subsets of ports, with
port translations, are also configurable.

UDP ephemeral ports are bound dynamically, as the guest uses them.

If all ports are forwarded, service proxies and other services running in the
container need to be started before _passt_ starts.

### pasta

With default options, _pasta_ scans for bound ports on init and non-init
namespaces, and automatically forwards them from the other side. Port forwarding
is fully configurable with command line options.

## Try it

### passt

* build from source:

        git clone https://passt.top/passt
        cd passt
        make

    * alternatively, install one of the [available packages](#availability)

        Static binaries and packages are simply built with:

            make pkgs

* have a look at the _man_ page for synopsis and options:

        man ./passt.1

* run the demo script, that detaches user and network namespaces, configures the
  new network namespace using `pasta`, starts `passt` and, optionally, `qemu`:

        doc/demo.sh

* alternatively, you can use
  [libvirt](https://libvirt.org/formatdomain.html#userspace-slirp-or-passt-connection)
  to start QEMU

* and that's it, you should now have TCP connections, UDP, and ICMP/ICMPv6
  echo working from/to the guest for IPv4 and IPv6

* to connect to a service on the VM, just connect to the same port directly
  with the address of the current network namespace

### pasta

* build from source:

        git clone https://passt.top/passt
        cd passt
        make

    * alternatively, install one of the [available packages](#availability)

        Static binaries and packages are simply built with:

            make pkgs

* have a look at the _man_ page for synopsis and options:

        man ./pasta.1

* start pasta with:

        ./pasta

    * alternatively, use it directly with Podman (since Podman 4.3.2, or with
      commit [`aa47e05ae4a0`](https://github.com/containers/podman/commit/aa47e05ae4a0d14a338cbe106b7eb9cdf098a529)):

            podman run --net=pasta ...

* you're now inside a new user and network namespace. For IPv6, SLAAC happens
  right away as _pasta_ sets up the interface, but DHCPv6 support is available
  as well. For IPv4, configure the interface with a DHCP client:

        dhclient

    and, optionally:

        dhclient -6

    * alternatively, start pasta as:

            ./pasta --config-net

        to let pasta configure networking in the namespace by itself, using
        `netlink`

    * ...or run the demo script:

            doc/demo.sh

* and that's it, you should now have TCP connections, UDP, and ICMP/ICMPv6
  echo working from/to the namespace for IPv4 and IPv6

* to connect to a service inside the namespace, just connect to the same port
  using the loopback address.
