#ifndef __UTILS_H
#define __UTILS_H

#include <string>
#include <deque>
#include "graph/Edge.h"
#include "graph/Node.h"

#define PATH_MAX 4096
// long型变量转换为字符串后的最大长度
#define LONG_STR_SIZE 15

void parse_opt(int argn, char** argv, unsigned int* p_tgid, char* filepath, int bufsize, int *stop);
int str_list_to_str(std::deque<std::string>* list, char* buf, int buf_size);
int int_list_to_str(std::deque<unsigned long>* list, char* buf, int buf_size);
unsigned long get_os_cpu_time();
unsigned long get_proc_cpu_time(unsigned int pid);
unsigned int get_proc_mem(unsigned int pid);
int delete_edge(Edge* edge);
int delete_node(Node* node);
Json::Value get_docker_list();
std::string get_service_name_by_port(int port);
std::string get_service_name_by_unix_socket(const std::string& socket_path);
#endif