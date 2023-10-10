# Agith

Agith is a tracing tool mainly based on eBPF technology, which can trace the impact of changes from the change command, including files, processes, and network sockets.

Features:

- An open-source tracing tool that capture the impact of changes from the command.
- Efficient, easy to use, and extensible
- Monitoring changes of files, processes, and network sockets.
  - File: creation, modification, and deletion
  - Process: creation, execution, and exit
  - Network socket: creation, connection, and closure

## Background

With rapid development of cloud computing, software updates and cloud changes have become increasingly important in maintaining system security and stability. However, cloud changes, in particular, can be a majoy cause of service failures and anomalies. Therefore, it has become essential to monitor the details of change actions during cloud changes.

Agith is developed to address this requirement. By using system technology to trace the impact of change commands, Agith provides operators with real-time information on system level changes, and allowing them to quickly identify and resolve issues that may arise during cloud changes.

Without proper monitoring and analysis tools like Agith, even minor changes to a system can result in major issues and downtime. Agith fills this gap by providing a powerful, easy-to-use, and extensible tracing tool that helps ensure the reliability and stability of cloud computing systems.

## Directory Structure

```shell
.
├── build.sh                # program building script
├── config                  # configuration files
├── doc                     # document supplement
├── include                 # headers files
├── libbpf -> ../libbpf     # libbpf symbol link
├── License.txt             # License
├── README.md               # README
├── src                     # source codes
└── test                    # test codes
```

## Program Structure

![Program Structure](./doc/structure.png)

## Installation

This project is used for Linux openEuler, and eBPF should be enabled in kernel.

### Environment

openEuler 20.03 LTS

Linux Kernel version at least: 4.19.90

Recommend kernel: Linux 4.19.90-2003.4.0.0036.oe1.x86_64

### Requirement

```
libbpf == v1.2
googletest == v1.12.1
elfutils-devel == 0.180-1.oe1
clang == 10.0.1-1.oe1
llvm ==  10.0.1-1.oe1
spdlog == v1.11.0
jsoncpp-devel == 1.9.3-2.oe1
```

## Usage

1. Install all requirements, symbollink libbpf to the project path
2. Compile program: run `./build.sh compile`
3. Run test case to check program availability: run `./build.sh test`

## Contributing

Feel free to dive in! Open an issue or submit PRs.

## Acknowledge

| Author             | Email                             |
| ------------------ | --------------------------------- |
| Shangguan Dongdong | shangguandongdong1@huawei.com     |
| Liu Chang          | chang-liu22@mails.tsinghua.edu.cn |
| Li Haozhe          | hzli@stu.pku.edu.cn               |
| Gao Yurui          | gaoyr19@mails.tsinghua.edu.cn     |

## License

[Mulan PSL](License.txt)
