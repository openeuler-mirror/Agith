set -e

shell_dir=$(dirname $(readlink -f "$0"))
build_dir=$shell_dir/build
DEP_FILES_DIR=${shell_dir}

function prepare_dep()
{
    # 1.
    echo "Step 1: clear tmp files"
    rm -rf /root/linux-build/
    rm -rf ./linux-build/

    # 2.
    mkdir linux-build
    cd linux-build

    yum install -y cmake
	yum -y install libdwarf-debuginfo.x86_64 libdwarf-devel.x86_64 libdwarf-tools.x86_64
	yum -y install elfutils-libs.x86_64  elfutils-devel.x86_64  elfutils-libelf-devel.x86_64
	yum -y install dwarves.x86_64 dwarves-debuginfo.x86_64
	yum -y install libdwarves1-devel.x86_64

    # 3. 
    # install_pahole
}

function install_pahole()
{
    # 1 check pahole already installed
    PAHOLE_VERSION=`pahole --version`
    if [ ${PAHOLE_VERSION} != "v1.20" ]; then
        return 0
    fi

    echo "Pahole v1.20 is not installed. Please install pahole == v1.20 first."
}

function compile_kernel()
{
    yum download --source kernel
    rpm2cpio kernel*.rpm | cpio -div
    tar -xvf kernel.tar.gz
    cd kernel
    make oldconfig
    make -j8
    pahole -J vmlinux
    bpftool btf dump file vmlinux format c > vmlinux.h # need to update bpftool
    cp vmlinux.h ${DEP_FILES_DIR}/
}

function prepare_build()
{
    yum -y groupinstall "development tools"
    yum -y install elfutils-libelf-devel
}

function clean(){
    echo "clean build directory..."
    if [ -d $build_dir ];then
        rm -rf $build_dir
    fi    
}

function check_vmlinux() {
    cd $shell_dir/src/BPF
    if [ -f "vmlinux.h" ]; then
        cd $shell_dir
        return 0
    fi

    yum install bpftool -y
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
}

function compile(){
    check_vmlinux
    if [ ! -d $build_dir ];then
        mkdir -p $build_dir
    fi      
    cd $build_dir
    cmake ..
    make -j
}

function build_vmlinux()
{
    # build vmlinux 
    if [ -f /sys/fs/bpf/vmlinux ]; then
        echo "==== vmlinux exist!"
        exit
    fi
    
    prepare_dep
    prepare_build
    compile_kernel
}

function build_rpm()
{
    # 创建rpm目录
    rpm_dir=~/rpmbuild
    if [ -d $rpm_dir ]; then
        rm -rf $rpm_dir
        rm -f $shell_dir/rpmbuild
    fi

    mkdir -p $rpm_dir/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    ln -s $rpm_dir $shell_dir/rpmbuild

    # copy executive file to rpmbuild/BUILD
    cd $shell_dir
    tar -czf Agith-0.1.tar.gz config include src build.sh
    mv Agith-0.1.tar.gz $rpm_dir/SOURCES
    cp $shell_dir/config/agith.spec $rpm_dir/SPECS/

    # 打包
    cd $rpm_dir
    rpmbuild -ba SPECS/agith.spec

    # 安装
    # rpm -ivh $rpm_dir/RPMS/x86_64/Agith-0.1-1.x86_64.rpm

    # # 卸载
    # rpm -e Agith-0.1-1.x86_64

}

function cpu_mem_util()
{   
    sleep 4
    cd $build_dir
    time=$(date "+%Y-%m-%d_%H-%M-%S")
    top -b -d 5 -p `pidof agith` > $time.perf 
}

function pre_task()
{
    compile
    nohup $shell_dir/build.sh perf > /dev/null 2>&1 &
    sleep 1    
}

function post_task()
{
    set +e
    kill -9 `pidof top`
    /usr/bin/python3 $shell_dir/tool/data_analyse.py  
    /usr/bin/python3 $shell_dir/tool/neo4j_loader.py   
}



if [ $# -eq 0 ]
then
    clean
    compile
    exit 0
fi

case $1 in
    perf)
        cpu_mem_util
        ;;
    clean)
        clean
        ;;
    compile)
        compile
        ;;
    build_vmlinux)
        build_vmlinux
        ;;
    build_rpm)
        build_rpm
        ;;
    post_task)
        post_task
        ;;
    pre_task)
        pre_task
        ;;
    *)
        echo "wrong option!"
        ;;
esac
 