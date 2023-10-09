Name:           Agith  
Version:        0.1
Release:        1%{?dist}
Summary:        Agith is a tracing tool mainly based on eBPF technology, which can trace the impact of changes from the change command, including files, processes, and network sockets

License:        MuLan PSL
URL:            https://gitee.com/openeuler/Agith
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  clang >= 10.0.1, llvm, elfutils-devel, jsoncpp-devel, log4cplus-devel, libbpf-devel
Requires:       libbpf, log4cplus

%description
Agith is a tracing tool mainly based on eBPF technology, which can trace the impact of changes from the change command, including files, processes, and network sockets

%prep
cd %{_sourcedir}
cp %{name}-%{version}.tar.gz %{_builddir}
cd %{_builddir}
tar -xzf %{name}-%{version}.tar.gz

%build
cd %{_builddir}
./build.sh compile

%install
mkdir -p %{buildroot}/usr/lib/agith/
cd %{_builddir}/build
cp agith %{buildroot}/usr/lib/agith/
cp -a BPF %{buildroot}/usr/lib/agith/
cp -a config %{buildroot}/usr/lib/agith/

# %pre
%post
ln -s /usr/lib/agith/agith /bin/agith

# %preun

%postun
rm -rf /bin/agith

%clean
rm -rf %{_builddir}/*

%files
/usr/lib/agith

%changelog