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
translations, using the _splice_(2) and _recvmmsg_(2)/_sendmmsg_(2) sysm calls
