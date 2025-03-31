#include <dirent.h>
#include <regex>
#include "model/BPFLoader.h"
#include "BPF/map_user.h"
#include <net/if.h>

#ifndef MAX_ERRNO
#define MAX_ERRNO 4095
#define IFACE "lo"
#endif

static inline bool IS_ERR(const void* ptr) {    
    return (unsigned long)ptr >= (unsigned long)-MAX_ERRNO;
}

BPFLoader::BPFLoader() {
    m_log = LoggerFactory::create_logger("BPFLoader");
    m_map_obj = NULL;
}

int BPFLoader::init(Json::Value config) {
    std::regex reg("[a-z]+\\.o");
    DIR* dirp = NULL;
    struct dirent* dir_entry = NULL;
    std::string dir_path, filename;
    dir_path = config["path"].asString();

    if ((dirp = opendir(dir_path.c_str())) == NULL) {
        log_error("missing BPF folder: %s", dir_path.c_str());
        return ENOENT;
    }

    while ((dir_entry = readdir(dirp)) != NULL) {
        if (dir_entry->d_type != DT_REG) continue;
        if (!std::regex_match(dir_entry->d_name, reg)) continue;

        filename = std::string(dir_entry->d_name);
        if (filename == "map.o") {
            m_map_file_path = dir_path + "/" + filename;
        } else {
            m_prog_file_path_list.push_back(dir_path + "/" + filename);
        }
    }

    if (m_map_file_path.size() == 0) {
        log_error("not found map.o");
        return ENOENT;
    }
    return 0;
}

int BPFLoader::load_map() {
    int ret;

    m_map_obj = bpf_object__open(m_map_file_path.c_str());
    if (m_map_obj == NULL) {
        log_error("fail to open %s", m_map_file_path.c_str());
        return -1;
    }
   
    ret = bpf_object__load(m_map_obj);
    if (ret) {
        log_error("fail to load %s", m_map_file_path.c_str());
        return -1;
    }

    return 0;
}

int BPFLoader::load_all_prog() {
    for (std::string prog_file_path : m_prog_file_path_list) {
        // 判断tc.o则调用load_tc_prog
        if(prog_file_path.substr(prog_file_path.find_last_of("/") + 1) == "tc.o"){
            if(load_tc_prog(prog_file_path.c_str())){
                log_error("load %s failed", prog_file_path.c_str());
                return -1;
            }
        }else{
            log_info("file name: %s", prog_file_path.c_str());
            if (load_prog(prog_file_path.c_str())) {
                log_error("load %s failed", prog_file_path.c_str());
                return -1;
            }  
        }      
    }
    return 0;
}

int BPFLoader::load_prog(const char* file_path) {
    struct bpf_object* obj;
    struct bpf_program* prog;
    struct bpf_link* link;
    int ret;

    obj = bpf_object__open(file_path);
    if (IS_ERR(obj)) {
        log_error("fail to open bpf prog %s", file_path);
        return -1;
    }

    ret = reuse_map_fd(obj);
    if (ret) {
        log_error("fail to reuse map %s fd", file_path);
        return -1;
    }

    ret = bpf_object__load(obj);
    if (ret) {
        log_error("fail to load prog %s", file_path);
        return -1;
    }

    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (link == NULL) {
            log_error("fail to attach %s, error code %d", bpf_program__name(prog), errno);
            return -1;
        }
    }

    m_prog_obj_list.push_back(obj);
    return 0;
}
int BPFLoader::load_tc_prog(const char* file_path){    
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, ifindex;
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts opts = {};
    int ret;
    // 1.打开bpf对象文件
    obj = bpf_object__open_file(file_path, NULL);
    if (IS_ERR(obj)) {
        log_error("fail to open bpf prog %s", file_path);
        return 0;
    }
    ret = reuse_map_fd(obj);
    // 2.加载bpf程序
    ret = bpf_object__load(obj);
    if (ret) {
        log_error("fail to load prog %s", file_path);
        return 0;
    }
     // 3.查找 BPF 探针程序
     prog = bpf_object__find_program_by_name(obj, "capture_packet");
     if (!prog) {
         fprintf(stderr, "Failed to find program\n");
         return 0;
     }
     // 获取 eBPF 程序文件描述符
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        return 0;
    }

    // 获取网络设备索引
    ifindex = if_nametoindex(IFACE);
    if (!ifindex) {
        perror("if_nametoindex");
        return 0;
    }
    // 删除 clsact 队列
    std::string cmd = "tc qdisc del dev " + std::string(IFACE) + " clsact";
    if (system(cmd.c_str()) == 0) {
        log_info("Successfully deleted clsact qdisc");
    } 
    // 绑定到 tc ingress
    hook.sz = sizeof(hook); 
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;
    // if (bpf_tc_hook_destroy(&hook) == 0) {
    //     log_info("Successfully destroyed existing tc hook");
    // } else {
    //     log_warn("No existing tc hook found or failed to destroy");
    // }
    if (bpf_tc_hook_create(&hook)) {
        log_error("Failed to create tc hook\n");
        return 0;
    }
    // memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.prog_fd = prog_fd;
    opts.flags = BPF_TC_F_REPLACE;

    if (bpf_tc_attach(&hook, &opts)) {
        log_error("Failed to attach BPF program to tc\n");
        return 0;
    }
    m_prog_obj_list.push_back(obj);
    return 0;
}

int BPFLoader::reuse_map_fd(struct bpf_object* prog_obj) {
    struct bpf_map* map_dst;
    struct bpf_map* map_src;
    const char* map_name;
    int map_fd;

    bpf_object__for_each_map(map_dst, prog_obj) {
        map_name = bpf_map__name(map_dst);
        if (strncmp(map_name, ".rodata", sizeof(".rodata")-1) == 0){
            continue;
        }
        map_src = bpf_object__find_map_by_name(m_map_obj, map_name);

        if (map_src == NULL) {
            log_error("can't find map %s in map list", map_name);
            return -1;
        }

        map_fd = bpf_map__fd(map_src);
        if (bpf_map__reuse_fd(map_dst, map_fd)) {
            log_error("fail to replace map %s fd", map_name);
            return -1;
        }
    }
    return 0;
}

int BPFLoader::get_map_fd(const char* map_name) {
    struct bpf_map* map;
    map = bpf_object__find_map_by_name(m_map_obj, map_name);
    if (map == NULL) {
        return -1;
    }

    return bpf_map__fd(map);
}

BPFLoader::~BPFLoader() {
    for(struct bpf_object* obj : m_prog_obj_list) {
        bpf_object__close(obj);
    }
    bpf_object__close(m_map_obj);

    // 销毁 tc 钩子
    struct bpf_tc_hook hook = {};
    hook.sz = sizeof(hook);
    hook.ifindex = if_nametoindex(IFACE);
    hook.attach_point = BPF_TC_EGRESS;

    if (bpf_tc_hook_destroy(&hook) == 0) {
        log_info("Successfully destroyed tc hook");
    } else {
        log_warn("Failed to destroy tc hook or no existing tc hook found");
    }
}