#ifndef __BPFLoader_H
#define __BPFLoader_H
#include <libelf.h>
#include <gelf.h>
#include <vector>
#include <string>
#include <json/json.h>
#include "bpf/bpf.h"
#include "tool/Log.h"

class BPFLoader {
public:
    BPFLoader();
    int init(Json::Value conf);
    int load_map();
    int load_all_prog();
    int clean_kprobe();
    int get_map_fd(const char* map_name);

private:
    // return section id if found, once miss will return minus number
    int get_section_id_by_name(Elf* elf, const char* name, int start = 1);
    int get_section_id_by_type(Elf* elf, unsigned int type, int start = 1);
    const char* get_section_name(Elf* elf, int id);
    Elf_Data* get_section_data(Elf* elf, int id);
    int get_section_header(Elf* elf, int id, GElf_Shdr* shdr);
    int parse_rel_section(Elf* elf, int rel_section_id);
    int load_and_attach(Elf* elf, int prog_section_id);
    void delete_maps();
    int kern_version();
    int load_prog(const char* file_path);
    int parse_maps_section();
    int attach(const char* prog_name, int bpf_prog_fd);
    std::vector<struct bpf_map_data> m_maps;
    std::map<std::string, int> m_progs;
    std::map<std::string, int> m_events;

    std::string m_map_file_path;
    std::vector<std::string> m_prog_file_path_list;
    log4cplus::Logger m_log;
};
#endif