from neo4j import GraphDatabase
from tqdm import tqdm
import os
import time
import re

class Neo4jLoader:
    def __init__(self):
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

def list_files_with_suffix(folder_path, suffix):
    """列出指定目录下指定后缀的文件并按时间排序"""
    file_list = []
    for root, dirs, files in os.walk(folder_path, topdown=False):
        for file in files:
            if file.endswith(suffix):
                match = re.match(r"(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})", file)
                if match:
                    time_str = match.group(1)
                    tm = time.strptime(time_str, "%Y-%m-%d_%H-%M-%S")
                    ts = int(time.mktime(tm))
                    file_list.append((ts, os.path.join(root, file)))
    file_list.sort(reverse=True, key=lambda x: x[0])  # 按时间降序排序
    return [file[1] for file in file_list]

def display_files(files):
    """显示文件列表"""
    print("可选文件列表：")
    for idx, file in enumerate(files):
        print(f"{idx + 1}: {file}")
    print()

if __name__ == "__main__":
    folder_path = "/root/A/Agith/build/output"
    suffix = ".cypher"
    files = list_files_with_suffix(folder_path, suffix)

    if not files:
        print("未找到符合条件的文件！")
        exit()

    display_files(files)

    # 用户选择文件
    while True:
        try:
            choice = int(input("请输入要加载的文件序号: "))
            if 1 <= choice <= len(files):
                filepath = files[choice - 1]
                break
            else:
                print("输入的序号超出范围，请重新输入！")
        except ValueError:
            print("无效输入，请输入一个数字！")

    url = "bolt://127.0.0.1:7687"
    user = "neo4j"
    passwd = "abc123"

    loader = Neo4jLoader()
    loader.connect(url, user, passwd)
    loader.clean_database()
    loader.load_file(filepath)
    loader.close()
    print("完成加载文件：" + filepath)
