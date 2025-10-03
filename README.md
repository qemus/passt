<!---
SPDX-License-Identifier: GPL-2.0-or-later
Copyright (c) 2021-2022 Red Hat GmbH
Author: Stefano Brivio <sbrivio@redhat.com>
-->

<style scoped>
.mobile_hide {
  visibility: hidden;
  display: none;
}
img {
  visibility: hidden;
  display: none;
}
li {
  margin: 10px;
}

@media only screen and (min-width: 768px) {
  .mobile_hide {
    visibility: visible;
    display: inherit;
  }
  img {
    visibility: visible;
    display: inherit;
  }
  li {
    margin: 0px;
  }
}

.mobile_show {
  visibility: visible;
  display: inherit;
}
@media only screen and (min-width: 768px) {
  .mobile_show {
    visibility: hidden;
    display: none;
  }
}
</style>

# passt: Plug A Simple Socket Transport

_passt_ implements a translation layer between a Layer-2 network interface and
native Layer-4 sockets (TCP, UDP, ICMP/ICMPv6 echo) on a host. It doesn't
