import os


with open("./test.txt", "w") as file:
    file.write("hello, this is a test file")

with open("./test.txt", "r") as file:
    print(file.readlines())

os.remove("./test.txt")