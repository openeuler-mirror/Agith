#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <regex>
#include "model/BPFLoader.h"
#include "BPF/map_user.h"

BPFLoader::BPFLoader() {
    m_log = LoggerFactory::create_logger("BPFLoader");
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

int BPFLoader::get_section_id_by_name(Elf* elf, const char* name, int start) {
    GElf_Ehdr ehdr;
    GElf_Shdr shdr;
    Elf_Scn* scn;
    char* shname;

    if (gelf_getehdr(elf, &ehdr) == NULL) return -1;

    for (int i = start; i < ehdr.e_shnum; i++) {
        scn = elf_getscn(elf, i);
        if (!scn) continue;

        if (gelf_getshdr(scn, &shdr) == NULL) continue;

        if (shdr.sh_size == 0) continue;

        shname = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
        if (shname == NULL) continue;

        if (strcmp(name, shname) == 0) return i;
    }

    return -1;
}

int BPFLoader::get_section_id_by_type(Elf* elf, unsigned int type, int start) {
    GElf_Ehdr ehdr;
    GElf_Shdr shdr;
    Elf_Scn* scn;

    if (gelf_getehdr(elf, &ehdr) == NULL) return -1;

    for (int i = start; i < ehdr.e_shnum; i++) {
        scn = elf_getscn(elf, i);
        if (!scn) continue;

        if (gelf_getshdr(scn, &shdr) == NULL) continue;

        if (shdr.sh_type == type) return i;
    }

    return -1;
}

const char* BPFLoader::get_section_name(Elf* elf, int id) {
    GElf_Ehdr ehdr;
    GElf_Shdr shdr;
    Elf_Scn* scn;

    if (gelf_getehdr(elf, &ehdr) == NULL) return NULL;

    scn = elf_getscn(elf, id);
    if (!scn) return NULL;

    if (gelf_getshdr(scn, &shdr) == NULL) return NULL;

    return elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
}

Elf_Data* BPFLoader::get_section_data(Elf* elf, int id) {
    Elf_Scn* scn;

    scn = elf_getscn(elf, id);
    if (!scn) return NULL;

    return elf_getdata(scn, NULL);
}

int BPFLoader::get_section_header(Elf* elf, int id, GElf_Shdr* shdr) {
    Elf_Scn* scn;

    scn = elf_getscn(elf, id);
    if (!scn) return -1;

    if (gelf_getshdr(scn, shdr) != NULL) return -1;
    return 0;
}

void BPFLoader::delete_maps() {
    for (struct bpf_map_data map : m_maps) {
        free(map.name);
    }
    m_maps.clear();
}

int BPFLoader::load_map() {
    delete_maps();
    if (parse_maps_section()) {
        log_error("load maps in elf file failed");
        return -1;
    }

    std::vector<struct bpf_map_data>::iterator map;
    for (map = m_maps.begin(); map < m_maps.end(); map++) {
        if (map->def.type == BPF_MAP_TYPE_ARRAY_OF_MAPS || map->def.type == BPF_MAP_TYPE_HASH_OF_MAPS) {
            log_warn("encountor map of map type %d", map->def.type);
            continue;
        }

        map->fd = bpf_create_map((enum bpf_map_type)map->def.type, map->def.key_size, map->def.value_size,
                                 map->def.max_entries, map->def.map_flags);
        if (map->fd < 0) {
            log_error("failed to create a map: %s\n", strerror(errno));
            return -1;
        }
    }
    return 0;
}

int BPFLoader::parse_maps_section() {
    Elf* elf;
    int ret = -1;
    int fd, map_section_id, sym_section_id, str_section_id;
    int sym_num, map_size;
    Elf_Data* map_section_data;
    Elf_Data* sym_section_data;
    GElf_Shdr sym_section_head;
    GElf_Sym sym;
    struct bpf_map_data map_data;
    struct bpf_map_def* map_def;
    char* map_name;

    if (elf_version(EV_CURRENT) == EV_NONE) return 1;

    fd = open(m_map_file_path.c_str(), O_RDONLY, 0);
    if (fd < 0) return 1;

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) goto done;

    map_section_id = get_section_id_by_name(elf, "maps");
    if (map_section_id < 0) {
        log_error("not found maps section in %s", m_map_file_path.c_str());
        goto done;
    }
    map_section_data = get_section_data(elf, map_section_id);

    sym_section_id = get_section_id_by_type(elf, SHT_SYMTAB);
    sym_section_data = get_section_data(elf, sym_section_id);

    get_section_header(elf, sym_section_id, &sym_section_head);
    // sym_section_head的sh_link是符号表中符号名所在字符串节的索引
    str_section_id = sym_section_head.sh_link;

    sym_num = sym_section_data->d_size / sizeof(GElf_Sym);
    for (int i = 0; i < sym_num; i++) {
        if (!gelf_getsym(sym_section_data, i, &sym)) continue;
        // sym.st_shndx是该符号对应变量或函数所在节的索引
        if (sym.st_shndx != map_section_id) continue;
        // sym.st_name是符号名在字符串节中的偏移量
        map_name = elf_strptr(elf, str_section_id, sym.st_name);
        map_data.name = strdup(map_name);
        map_data.fd = -1;
        // sym.st_value是符号对应变量或函数在section中偏移量
        map_def = (struct bpf_map_def*)((char*)map_section_data->d_buf + sym.st_value);
        memcpy(&map_data.def, map_def, sizeof(struct bpf_map_def));
        m_maps.push_back(map_data);
    }

    map_size = map_section_data->d_size / m_maps.size();
    if (map_size != sizeof(struct bpf_map_def)) {
        log_error("bpf_map_def size %lu not equal to maps section size %d", sizeof(struct bpf_map_def), map_size);
        goto done;
    }

    ret = 0;
done:
    close(fd);
    return ret;
}

int BPFLoader::load_all_prog() {
    for (std::string prog_file_path : m_prog_file_path_list) {
        if (load_prog(prog_file_path.c_str())) {
            log_error("load %s failed", prog_file_path.c_str());
            return -1;
        }
    }
    return 0;
}

int BPFLoader::load_prog(const char* file_path) {
    Elf* elf;
    int ret = -1;
    int fd, rel_section_id, prog_section_id;

    if (elf_version(EV_CURRENT) == EV_NONE) return 1;

    fd = open(file_path, O_RDONLY, 0);
    if (fd < 0) return -1;

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) goto done;

    rel_section_id = 0;
    while ((rel_section_id = get_section_id_by_type(elf, SHT_REL, rel_section_id + 1)) > 0) {
        if (parse_rel_section(elf, rel_section_id)) {
            log_error("parse rel section %d failed", rel_section_id);
            goto done;
        }
    }

    prog_section_id = 0;
    while ((prog_section_id = get_section_id_by_type(elf, SHT_PROGBITS, prog_section_id + 1)) > 0) {
        load_and_attach(elf, prog_section_id);
    }
    ret = 0;
done:
    close(fd);
    return ret;
}

/**
 * @brief 首先获取rel对应的prog section。从section data中读取BPF指令。将指令中的map替换为已经创建的map的fd
 *
 * @param elf
 * @param rel_section_id
 * @return int
 */
int BPFLoader::parse_rel_section(Elf* elf, int rel_section_id) {
    int i, nrels;
    Elf_Data* rel_section_data;
    Elf_Data* sym_section_data;
    Elf_Data* prog_section_data;
    struct bpf_insn* insns;
    GElf_Sym sym;
    GElf_Rel rel;
    int prog_section_id, sym_section_id, str_section_id;
    GElf_Shdr rel_section_head;
    GElf_Shdr prog_section_head;
    GElf_Shdr sym_section_head;
    unsigned int insn_idx;
    char* map_name;
    // 获取rel section对应的prog section
    get_section_header(elf, rel_section_id, &rel_section_head);
    prog_section_id = rel_section_head.sh_info;
    get_section_header(elf, prog_section_id, &prog_section_head);

    // 非BPF程序的section不需要处理
    if (prog_section_head.sh_type != SHT_PROGBITS || !(prog_section_head.sh_flags & SHF_EXECINSTR)) return 0;

    // 提取BPF指令
    prog_section_data = get_section_data(elf, prog_section_id);
    insns = (struct bpf_insn*)prog_section_data->d_buf;

    rel_section_data = get_section_data(elf, rel_section_id);
    sym_section_id = get_section_id_by_type(elf, SHT_SYMTAB);
    sym_section_data = get_section_data(elf, sym_section_id);
    get_section_header(elf, sym_section_id, &sym_section_head);
    str_section_id = sym_section_head.sh_link;

    nrels = rel_section_head.sh_size / rel_section_head.sh_entsize;
    for (i = 0; i < nrels; i++) {
        gelf_getrel(rel_section_data, i, &rel);
        insn_idx = rel.r_offset / sizeof(struct bpf_insn);

        // rel section的info项高32位是重定位符号在符号表中的索引号
        // info低32位是重定位类型
        gelf_getsym(sym_section_data, GELF_R_SYM(rel.r_info), &sym);
        map_name = elf_strptr(elf, str_section_id, sym.st_name);

        // 需要重定位的指令类型
        if (insns[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW)) {
            log_error("invalid relo for insn[%d].code 0x%x", insn_idx, insns[insn_idx].code);
            return -1;
        }
        insns[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;

        insns[insn_idx].imm = -1;
        for (struct bpf_map_data map_data : m_maps) {
            if (strcmp(map_data.name, map_name) == 0) {
                insns[insn_idx].imm = map_data.fd;
                break;
            }
        }
        if (insns[insn_idx].imm < 0) {
            log_error("can't find map %s when relocate bpf prog", map_name);
            return -1;
        }
    }

    return 0;
}

int BPFLoader::kern_version() {
    struct utsname u;
    if (uname(&u)) {
        printf("Error: can't get linux release info\n");
        return -1;
    }

    std::string release = u.release;
    int n1 = 0, n2 = 0;
    int version = 0;
    int patch = 0;
    int sub_patch = 0;

    n2 = release.find('.', n1);
    version = atoi(release.substr(n1, n2 - n1).c_str());
    n1 = n2 + 1;

    n2 = release.find('.', n1);
    patch = atoi(release.substr(n1, n2 - n1).c_str());
    n1 = n2 + 1;

    n2 = release.find('-', n1);
    sub_patch = atoi(release.substr(n1, n2 - n1).c_str());
    n1 = n2 + 1;

    auto is_real = [](int a) -> bool { return a > 0 && a < 100; };

    if (is_real(version) && is_real(patch)) {
        return (version << 16) + (patch << 8) + sub_patch;
    } else {
        printf("Error: get wrong release info: %s", release.c_str());
        return -1;
    }
}

int BPFLoader::load_and_attach(Elf* elf, int prog_section_id) {
    int license_section_id;
    const char* prog_section_name;
    enum bpf_prog_type prog_type;
    Elf_Data* license_section_data;
    Elf_Data* prog_section_data;
    std::string prog_name;
    struct bpf_insn* insns;
    int insn_num;
    char* bpf_log_buf;
    int prog_fd, event_fd;
    int ret = -1;

    // BPF_LOG_BUF_SIZE太大，声明为数组会导致函数栈溢出，必须在堆上分配。
    bpf_log_buf = (char*)malloc(BPF_LOG_BUF_SIZE);
    prog_section_name = get_section_name(elf, prog_section_id);
    if (strncmp(prog_section_name, "kprobe/", 7) == 0) {
        prog_type = BPF_PROG_TYPE_KPROBE;
    } else if (strncmp(prog_section_name, "kretprobe/", 10) == 0) {
        prog_type = BPF_PROG_TYPE_KPROBE;
    } else if (strncmp(prog_section_name, "tracepoint/", 11) == 0) {
        prog_type = BPF_PROG_TYPE_TRACEPOINT;
    } else {
        // log_warn("encountor unknown prog type %s", prog_section_name);
        ret = 0;
        goto done;
    }

    // 获取证书
    license_section_id = get_section_id_by_name(elf, "license");
    if (license_section_id < 0) {
        log_error("license section missing");
        goto done;
    }
    license_section_data = get_section_data(elf, license_section_id);

    prog_name = prog_section_name;
    if (m_progs.find(prog_name) != m_progs.end()) {
        log_error("bpf probe %s has existed", prog_section_name);
        goto done;
    }
    prog_section_data = get_section_data(elf, prog_section_id);
    insns = (struct bpf_insn*)prog_section_data->d_buf;
    insn_num = prog_section_data->d_size / sizeof(struct bpf_insn);

    prog_fd = bpf_load_program(prog_type, insns, insn_num, (char*)license_section_data->d_buf, kern_version(),
                               bpf_log_buf, BPF_LOG_BUF_SIZE);
    if (prog_fd < 0) {
        log_error("load prog %s failed, %s", prog_section_name, bpf_log_buf);
        goto done;
    }

    event_fd = attach(prog_section_name, prog_fd);
    if (event_fd < 0) {
        log_error("attach prog %s failed", prog_section_name);
        goto done;
    }

    m_progs[prog_name] = prog_fd;
    m_events[prog_name] = event_fd;
    ret = 0;
done:
    free(bpf_log_buf);
    return ret;
}

int BPFLoader::attach(const char* prog_name, int bpf_prog_fd) {
    std::string event_name;
    std::string type_name;
    int ret, fd;
    size_t pos;
    int buf_size = 1024;
    char buf[buf_size];
    struct perf_event_attr attr = {};

    type_name = prog_name;
    pos = type_name.find('/');
    if (pos == std::string::npos) {
        log_error("prog name %s is wrong", prog_name);
        return -1;
    }

    event_name = type_name.substr(pos + 1, std::string::npos);
    type_name = type_name.substr(0, pos);

    // kprobe相比tracepoint需要手动写入探针位置
    if (type_name == "kretprobe" || type_name == "kprobe") {
        snprintf(buf, buf_size, "echo '%c:%s %s' >> /sys/kernel/debug/tracing/kprobe_events",
                 type_name == "kprobe" ? 'p' : 'r', event_name.c_str(), event_name.c_str());

        ret = system(buf);
        if (ret < 0) {
            log_error("failed to create kprobe %s, %s", event_name.c_str(), strerror(errno));
            return -1;
        }
        snprintf(buf, buf_size, "/sys/kernel/debug/tracing/events/kprobes/%s/id", event_name.c_str());
    } else if (type_name == "tracepoint") {
        snprintf(buf, buf_size, "/sys/kernel/debug/tracing/events/%s/id", event_name.c_str());
    }

    fd = open(buf, O_RDONLY, 0);
    if (fd < 0) {
        log_error("failed to open event %s, %s", buf, strerror(errno));
        return -1;
    }

    ret = read(fd, buf, buf_size);
    if (ret < 0 || ret >= buf_size) {
        log_error("read from %s failed %s", buf, strerror(errno));
        return -1;
    }
    buf[ret] = 0;
    close(fd);

    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.config = atoi(buf);

    // perf_evet_open(perf_event_attr, pid, cpu, group_fd, flag)
    fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
    if (fd < 0) {
        log_error("create perf event %s failed, %s", event_name.c_str(), strerror(errno));
        return -1;
    }
    ioctl(fd, PERF_EVENT_IOC_SET_BPF, bpf_prog_fd);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    return fd;
}

int BPFLoader::get_map_fd(const char* map_name) {
    for (struct bpf_map_data map : m_maps) {
        if (strcmp(map_name, map.name) == 0) {
            return map.fd;
        }
    }
    return -1;
}

int BPFLoader::clean_kprobe() {
    /* clear all kprobes, TODO: 清理Kprobe对系统的影响需要考虑*/
    int ret = system("echo \"\" > /sys/kernel/debug/tracing/kprobe_events");
    if (ret) {
        log_warn("clean kprobe failed, %s", strerror(errno));
    }
    return ret;
}