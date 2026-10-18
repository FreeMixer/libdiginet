# SPDX-License-Identifier: GPL-3.0-or-later
# libdiginet, the protocol of the Digidesign Control|24 and ProControl surfaces, and
# libdiginet-transport, the wire under it, from one source and one version; diginet-tools
# carries diginet-probe.
Name:           libdiginet
Version:        0.1.0
# The sonames' majors. rpm derives this package's provides and every consumer's requires from
# them. They copy DIGINET_ABI and DIGINET_TRANSPORT_ABI of include/diginet/diginet.h, and
# tests/conformance-packaging.sh (in make test) refuses a copy that disagrees.
%global abi 0
%global tabi 0
Release:        1%{?dist}
Summary:        Drive a Digidesign Control|24 or ProControl surface from Linux

License:        GPL-3.0-or-later
URL:            https://github.com/FreeMixer/libdiginet
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  git-core
BuildRequires:  pkgconf-pkg-config

%description
libdiginet speaks DigiNet, the raw Ethernet protocol of the Digidesign Control|24 and
ProControl control surfaces, so a Linux mixer or DAW can drive one again: motor faders and
their touch, V-Pots and their LED rings, every key and lamp, scribble strips, meters, the
counter and the jog wheel.

This package holds two shared libraries. libdiginet is the protocol: the frame grammar,
encoders and decoders for every control, and one personality per desk; it refuses to encode
the desk's memory-writing message family. libdiginet-transport is the wire: the packet
socket, discovery, the online handshake, acknowledgements, a keepalive that ACKs never
starve, retransmit, back-off, latest-wins coalescing and display pacing. It never wakes a
desk another host is using.

%package devel
Summary:        Development files for libdiginet and libdiginet-transport
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
Headers, pkg-config files (libdiginet, libdiginet-transport) and the Kaitai Struct grammar of
the protocol, diginet.ksy, for building programs that drive a Control|24 or ProControl.

%package -n diginet-tools
Summary:        diginet-probe: the first test of a Control|24 or ProControl
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description -n diginet-tools
diginet-probe wakes a Control|24 or ProControl cabled to a network interface, moves a fader,
lights a lamp, writes a scribble strip, logs and decodes every key, touch and turn, and ends
with a summary of what the desk answered. It is installed with the one capability it needs
to open a packet socket, cap_net_raw.

%prep
%autosetup -n %{name}-%{version}

%build
%make_build CFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}" shared

%install
%make_install PREFIX=%{_prefix} LIBDIR=%{_libdir} INCDIR=%{_includedir} BINDIR=%{_bindir} \
  DATADIR=%{_datadir} MANDIR=%{_mandir} install-shared

%check
make CFLAGS="%{optflags}" test

%files
%license LICENSE
%doc README.md
%{_libdir}/libdiginet.so.%{version}
%{_libdir}/libdiginet.so.%{abi}
%{_libdir}/libdiginet-transport.so.%{version}
%{_libdir}/libdiginet-transport.so.%{tabi}

%files devel
%doc BUILDING.md docs/protocol.md
%dir %{_includedir}/diginet
%dir %{_includedir}/diginet/transport
%{_includedir}/diginet/*.h
%{_includedir}/diginet/transport/*.h
%{_libdir}/libdiginet.so
%{_libdir}/libdiginet-transport.so
%{_libdir}/pkgconfig/libdiginet.pc
%{_libdir}/pkgconfig/libdiginet-transport.pc
%dir %{_datadir}/diginet
%{_datadir}/diginet/diginet.ksy

%files -n diginet-tools
%doc docs/probe.md
%caps(cap_net_raw=ep) %{_bindir}/diginet-probe
%{_mandir}/man1/diginet-probe.1*

%changelog
