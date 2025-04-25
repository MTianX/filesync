# SFTP文件同步工具

这是一个基于Go语言开发的SFTP文件同步工具，用于将本地文件同步到远程服务器。

## 功能特点

- 支持多任务配置，每个任务可以独立配置源目录、目标服务器等参数
- 支持文件后缀过滤
- 支持最近修改时间过滤（可配置是否启用）
- 支持文件备份功能（可配置是否启用）
- 支持文件校验功能（可配置是否启用）
- 支持文件锁检查，避免传输正在写入的文件
- 支持文件校验失败自动重试
- 详细的日志记录

## 配置文件说明

配置文件采用YAML格式，示例：

```yaml
# 全局配置
scan_interval: 300  # 扫描间隔（秒）
verify_enabled: true  # 是否启用文件校验
max_retries: 3  # 文件校验失败最大重试次数

# 同步任务配置
sync_configs:
  - name: "任务1"  # 任务名称
    source_dir: "/path/to/source"  # 源目录
    backup_dir: "/path/to/backup"  # 备份目录
    file_extensions: [".txt", ".log"]  # 文件后缀
    modified_enabled: true  # 是否启用最近修改时间过滤
    modified_minutes: 1440  # 修改时间范围（分钟）
    backup_enabled: true  # 是否启用备份
    targets:  # 目标服务器列表
      - ip: "192.168.1.100"
        port: 22
        username: "user1"
        password: "pass1"
        target_dir: "/remote/path1"
      - ip: "192.168.1.101"
        port: 22
        username: "user2"
        password: "pass2"
        target_dir: "/remote/path2"

  - name: "任务2"
    source_dir: "/path/to/source2"
    backup_dir: "/path/to/backup2"
    file_extensions: [".csv"]
    modified_enabled: true
    modified_minutes: 720
    backup_enabled: false
    targets:
      - ip: "192.168.1.102"
        port: 22
        username: "user3"
        password: "pass3"
        target_dir: "/remote/path3"
```

## 文件锁检查说明

程序在传输文件前会进行文件锁检查，确保文件没有被其他进程写入。具体实现：

1. 使用Linux系统的`flock`机制检查文件是否被锁定
2. 如果文件被锁定，说明文件正在被写入，程序会跳过该文件
3. 文件锁检查可以有效避免传输不完整的文件

## 文件校验说明

程序在文件传输完成后会进行校验，确保文件完整性。具体实现：

1. 计算本地文件的MD5值
2. 计算远程文件的MD5值
3. 比较两个MD5值是否一致
4. 如果校验失败：
   - 记录失败信息到日志
   - 在下个扫描周期自动重试传输
   - 达到最大重试次数后，记录错误并跳过该文件

## 日志说明

程序运行时会生成详细的日志，包括：

- 任务开始和结束时间
- 文件传输状态
- 文件校验结果
- 文件锁检查结果
- 校验失败重试信息
- 错误信息（如果有）

## 使用说明

1. 配置`config.yaml`文件，设置源目录、目标服务器等信息
2. 编译程序：
   - 本地编译：`go build -o sftp_sync`
   - Linux交叉编译(PowerShell)：`$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o sftp_sync_linux sftp_sync.go`
3. 运行程序：
   - 本地版本：`./sftp_sync -config config.yaml`
   - Linux版本：`./sftp_sync_linux -config config.yaml`

## 注意事项

1. 确保目标服务器的SFTP服务正常运行
2. 确保有足够的磁盘空间用于文件备份
3. 文件锁检查功能仅在Linux系统上可用
4. 建议根据实际需求调整扫描间隔时间
5. 文件校验失败重试机制会在下个扫描周期自动执行
