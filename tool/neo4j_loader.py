from neo4j import GraphDatabase
from tqdm import tqdm
import os
import time
import matplotlib.pyplot as plt
    

class Neo4jLoader:
    def  __init__(self):
        self.driver = None

    def connect(self, url, user, password):
        self.driver = GraphDatabase.driver(url, auth=(user, password))

    def close(self):
        self.driver.close()

    def clean_database(self):
        txt = "MATCH (n) OPTIONAL MATCH (n)-[r]-() DELETE n,r"
        self.driver.execute_query(txt, database="neo4j")


    def load_file(self, filepath):
        data = list()
        with open(filepath) as file:
            data = file.readlines()

        session = self.driver.session(database="neo4j")
        for txt in tqdm(data):
            session.run(txt.strip())
        session.close()       
    
def find_newest_file(folder_path, suffix):
    newest_time = 0
    newest_file = None
    for root, dirs, files in os.walk(folder_path, topdown=False):
        for file in files:
            if not file.endswith(suffix):
                continue
            tm = time.strptime(file, "%Y-%m-%d_%H-%M-%S.cypher")
            ts = int(time.mktime(tm))
            if ts > newest_time:
                newest_time = ts
                newest_file = os.path.join(root, file)
    return newest_file

def parse_perf_file(file_path, fig_path):
    if not os.path.exists(file_path):
        return
    with open(file_path) as file:
        data = file.readlines()
    
    cpu_util = list()
    mem_util = list()
    for txt in data:
        txt_array = txt.strip().split()

        if len(txt_array) == 0 or txt_array[-1] != "agith":
            continue
        cpu_util.append(float(txt_array[8]))
        mem_util.append(float(txt_array[5]) / 1024)

    plt.figure(figsize=(20, 10))
    plt.subplot(1, 2, 1)
    plt.plot(cpu_util)
    plt.title("cpu")
    plt.xlabel("time")
    plt.ylabel("percent%")

    plt.subplot(1, 2, 2)
    plt.plot(mem_util)
    plt.title("memory")
    plt.xlabel("time")
    plt.ylabel("MB")
    plt.savefig(fig_path)
    if len(cpu_util) > 0:
        print("avg cpu utilization:", sum(cpu_util)/len(cpu_util))
        print("max cpu utilization:", max(cpu_util))
        print("max memory:", max(mem_util))

        
def parse_trace_file(path_file, fig_path):
    if not os.path.exists(path_file):
        return

    syscall_num_dict = dict()
    try:
        with open(path_file) as file:
            for line in file:
                if not line.startswith("pid:"):
                    continue
                syscall = line.split(",")[1].split(":")[1]
                if syscall in syscall_num_dict:
                    syscall_num_dict[syscall] += 1
                else:
                    syscall_num_dict[syscall] = 1
    except UnicodeDecodeError:
        print("text in trace file is not utf-8")
    syscall_list = list()
    num_list = list()
    for syscall in syscall_num_dict.keys():

        syscall_list.append(syscall)
        num_list.append(syscall_num_dict[syscall])

    plt.figure(figsize=[20,10])
    plt.bar(syscall_list, num_list)
    plt.savefig(fig_path)

    num = sum(num_list)
    print("trace num :", num)


if __name__ == "__main__":
    url = "bolt://192.168.10.8:7687"
    user = "neo4j"
    passwd = "sgdd123S"    
    filepath = find_newest_file("/root/Agith/build", ".cypher")
    loader = Neo4jLoader()
    loader.connect(url, user, passwd) 
    loader.clean_database()
    loader.load_file(filepath)
    loader.close()
    print("finish load file:" + filepath)

