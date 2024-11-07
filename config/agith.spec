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
mkdir -p %{buildroot}/tmp/log/Agith
mkdir -p %{buildroot}/usr/lib/agith/
mkdir -p %{buildroot}/usr/lib/agith/output
cp ssh.sh %{buildroot}/usr/lib/agith/

cd %{_builddir}/build
cp prod/agith %{buildroot}/usr/lib/agith/
%define __strip echo
cp -a prod/BPF %{buildroot}/usr/lib/agith/
cp -a prod/config %{buildroot}/usr/lib/agith/


%pre
if [ -f /etc/ssh/sshd_config ]; then
  if ! grep -q "^ForceCommand /usr/lib/agith/ssh.sh" /etc/ssh/sshd_config; then
    echo "ForceCommand /usr/lib/agith/ssh.sh" >> /etc/ssh/sshd_config
  fi
fi
if systemctl is-active sshd >/dev/null 2>&1; then
  systemctl reload sshd
fi

%post
ln -s /usr/lib/agith/agith /bin/agith
chmod +x /usr/lib/agith/ssh.sh

# %preun

%postun
rm -rf /bin/agith
# 删除增加的sshd配置
if [ -f /etc/ssh/sshd_config ]; then
  sed -i '/^ForceCommand \/usr\/lib\/agith\/ssh.sh/d' /etc/ssh/sshd_config
fi
if systemctl is-active sshd >/dev/null 2>&1; then
  systemctl reload sshd
fi

%clean
rm -rf %{_builddir}/*

%files
/usr/lib/agith

%changelog