from neo4j import GraphDatabase
import os
import time
    

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
        for txt in data:
            session.run(txt.strip())
        session.close()       
    

if __name__ == "__main__":
    url = "bolt://IP_ADDR:7687"
    user = "neo4j"
    passwd = "neo4j"    
    filepath = "..."

    loader = Neo4jLoader()
    loader.connect(url, user, passwd) 
    # loader.clean_database()
    loader.load_file(filepath)
    loader.close()
    print("finish load file:" + filepath)

