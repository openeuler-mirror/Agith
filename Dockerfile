# 基础镜像为 openeuler:22.03
FROM openeuler/openeuler:22.03

COPY . /Agith
RUN  rm -rf /etc/yum.repos.d/*
COPY openEuler.repo /etc/yum.repos.d/

# Prepare build dependencies
RUN yum clean all
RUN yum -y install jsoncpp.x86_64 \
                   log4cplus.x86_64\
                   elfutils.x86_64\
                   libbpf.x86_64\
                   util-linux.x86_64\
                   log4cplus-devel\
                   libbpf-devel\
                   jsoncpp-devel\
                   cmake\
                   make\
                   clang\
                   bpftool && \
    ldconfig
WORKDIR /Agith 
RUN rm -rf build   
    # Update the shared library cache
WORKDIR /Agith 
RUN ./build.sh compile
 
ENTRYPOINT ["/usr/bin/bash", "-c", "mount -t debugfs debugfs /sys/kernel/debug && ./agith -c config/agith.config \"$@\"", "--"]
CMD ["-p", "1"]
# ENTRYPOINT ["/usr/bin/sh", "-c", "mount -t debugfs debugfs /sys/kernel/debug && exec /bin/bash -i"]
# CMD ["-i"]



