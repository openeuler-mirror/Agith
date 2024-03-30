#include <dirent.h>
#include <regex>
#include "model/BPFLoader.h"
#include "BPF/map_user.h"

#ifndef MAX_ERRNO
#define MAX_ERRNO 4095
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
        log_info("file name: %s", prog_file_path.c_str());
        if (load_prog(prog_file_path.c_str())) {
            log_error("load %s failed", prog_file_path.c_str());
            return -1;
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
}