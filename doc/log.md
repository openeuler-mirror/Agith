# 设计日志

1. Node 类创建之后，需要根据 key 纳管到类静态的 map 中。有两种方式纳管，一种是在 new 一个新对象之后手动纳管。另一种方式是在构造函数中默认纳管。之前认为自动纳管的方式最方便，创建之后可以自动管理。但是现在发现这种方式会导致内存泄露。因为一旦两个对象的 key 相同。例如前后两个进程有相同的 pid，两个文件有相同的 inode，就会丢失之前创建的对象指针。在测试中这种问题更为严重。

现在的解决方法是统一采用手动纳管的方式。因为创建时可以检查 key 是否已经存在，从而避免重复创建。但是自动创建即使发现重复创建，也不能停止创建过程。此时已经在构造函数中，不能在构造函数中调用析构函数。

2. 在 output_part 中不建议删除 filenode。因为之后的进程极有可能是相同的命令，会调用相同的文件。如果删除了 FIlenode，之后绘图中会出现 graph_id 不同但是 inode 与文件名完全相同的节点。所以建议无效数据清除只清除已经结束的 ProcessNode。

对于 SocketNode 也有同样的担忧，因为删除之后也会出现相同的访问。但是 SocketNode 不必保存完整的报文数据，这个可以在 trace 数据中查询。为了方便，保存 50 字符应该就可以了。

3. get_wd()读取异常的原因是 trace 量过大时会发生丢失。如果之前丢失的是 clone 系统调用，那么之后这个新进程的任何系统调用都会排除掉。因为虽然有 trace，却找不到可以执行的 ProcessNode。只有 read 和 write 两个系统调用是例外。为了支持写后读的场景，不再目标之内的进程也可以仅根据 read 和 write 来创建一个 ProcessNode 节点。

4. 对于写后读的场景，有一种特殊情况会将无关进程纳入监控范围。当一个文件被删除之后，它的 inode 编号是会被重用的。假设我们写入一个文件。这个文件的 inode 编号就会被加入监控目标。之后这个文件被删除了。同时一个无关文件新建一个文件，恰好这个 inode 编号与被删除的文件相同。这个无关行为就会被纳入到监控范围内。消除这种情况的方法是监控 unlink 系统调用，将对应的 inode 编号从监控目标中删除。

5. socket 的整改比较困难，网络场景太复杂了。其中涉及到不同的协议，server 与 client 的角色差异、send/recv 与 write/read 的重复等等很多问题。现在遇到的问题是本地 socket 容易重复，冗余数据太多的问题。例如调用 vim 命令，会创建几十个 socket，导致拓扑过于复杂。

一开始的设计是想让 ProcessNode 直接链接目标端的 socketnode。但是这样做和 socket 的创建逻辑无法匹配。socket 系统调用可以获取 family，type，protocol，fd 四个关键参数。这个时候需要在 fd_table 中添加 fd:socket_node。但是这个时候目标地址还没有，所以没办法创建 SocketNode。当时想的办法就是创建一个本地 Socket，因为本地地址是知道的。当时也没有获取本地地址的方案，因为涉及到多个网卡的问题。所以这个就变成了遗留问题。在测试 vim 命令时，没有想到 vim 会启动大量的 socket 用于进程通讯。导致本地 socket 太多了。

目前两种整改方案。第一种是删除本地 socket，直接让 ProcessNode 关联目标 SocketNode。在 socket 系统调用中，先构建一个空的 SocketNode。等到 connect 系统调用时再填充地址，然后在添加 SocketNode::socket_nodes 中。这样做，就必须做好内存管理。防止出现内存泄露。

第二种是保留本地 socket，用本地 socket 去对接目标 socket。这里必须解决本地 socket 的重复问题。如果用 ip：port 来唯一标识估计不太可能。即使可以解决网卡问题，port 仍然很难获取。因为客户端的 port 都是发送时随机指定的。只有 server 的 bind 函数才能拿到准确的本地 ip+port。如果用 pid 来表示本地 socket，那么如果一个进程启动多个 socket 该如何处理？

比较来看。保留本地 socket 的意义不大，因为本地 socket 只有对 server 是有意义的。对于 client 是没有意义的。而且按照 ip+port 的模式来管理会更容易。但是 socket 系统调用还没有 ip 地址，所以暂时保管在 SocketNode 的 buf 中，在 connect 系统调用中再转移到 socket_nodes 中。然后 SocketNode 与 ProcessNode 直接关联。

6. 在 linux 中删除文件的系统调用和删除文件夹的系统调用是不同的，删除文件是 SYS_unlink,删除文件夹是 SYS_rmdir。但是奇怪的是使用 rm 命令删除文件夹也会触发 SYS_unlink，而且返回值也为 0.只是没有调用 vfs_unlink 函数，所以 inode 没有办法获取。

我一开始想增加 rmdir 系统调用的探针，但是觉得这样做用处不大，因为文件夹毕竟不是文件，很少会因为文件夹导致系统问题。而且既然删除文件夹也会触发 unlink 系统调用。虽然没有 inode 信息，但是有删除对象的文件名，应该也可以处理。

7. 使用 map 不能有效的过滤读写重复的 trace。因为当 map 数据满时，新的数据就会添加失败。这样之后的读写都会视为第一次，从而导致数据快速增长。我一开始想在满的时候将 map 中的数据全部删除，但是内核中缺乏对应的 helper。而且内核程序也不允许循环遍历，所以我没有办法将 map 清空。之后我在 close 系统调用触发时，删除 map 中对应的项。结果发现一段时间之后还是会满。这是由于在进程启动过程中，读取的很多静态库并没有对应的 close。而且这些数据很多，最终会将 map 写满。一种降低数据量的方法是采用<pid, syscall, fd>而不是<pid, syscall, inode>。因为前者会多次重复，而且一般都会调用 close。但是在测试中发现，使用前者会丢失数据。原因也是进程启动是打开的库。假设打开静态库的 fd 是 6，没有关闭。那么之后的向 fd 读取操作就都会被视为重复记录。从准确性而言使用 inode 会更加准确。另一种更好的方式，是先将这个 map 设置大一点，同时在用户态，间隔特定时间清空。

8. socket 系统调用带来很大的麻烦。首先 SocketNode 的是通过地址来管理的，socket 系统调用只是建立 socket，还没有分配地址。此时创建的 socket_node 不能通过地址管理，只能缓存在 process_node 的 fd_table 中。而且时间发现，很多 socket 系统调用不会有后续的 connect。所以这部分会永远缓存在 fd_table 中。在清理 process_node 时还需要检查这部分数据并手动清理。这种方式导致 socket_nodes 的管理难度加大。同时，这样做的收益也不大，socket 最重要的还是地址和数据。socket 可以提供的数据是 family，type，protocol。family 在 connect 也存在。唯一重要的是 type，区分 SOCK_DGRAM 与 SOCK_STREAM，也就是 UDP 与 TCP 的区别。但是这个数据在运维过程中意义不大。综上，建议还是放弃监控 socket 系统调用，从 connect 开始监控网络行为。避免 Agith 数据管理过于复杂与内存泄露。
