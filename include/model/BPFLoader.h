#ifndef __BPFLoader_H
#define __BPFLoader_H
#include <libelf.h>
#include <gelf.h>
#include <vector>
#include <string>
#include <json/json.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "tool/Log.h"

class BPFLoader {
public:
    BPFLoader();
    ~BPFLoader();
    int init(Json::Value conf);
    int load_map();
    int load_all_prog();
    int get_map_fd(const char* map_name);

private:
    int load_prog(const char* file_path);
    int reuse_map_fd(struct bpf_object* prog_obj);

    std::string m_map_file_path;
    std::vector<std::string> m_prog_file_path_list;
    log4cplus::Logger m_log;
    struct bpf_object* m_map_obj;
    std::vector<struct bpf_object*> m_prog_obj_list;
};
#endif