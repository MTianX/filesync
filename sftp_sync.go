package main

import (
	"crypto/md5"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Config 配置文件结构
type Config struct {
	SyncConfigs   []SyncConfig `yaml:"sync_configs"`
	ScanInterval  int          `yaml:"scan_interval"`  // 扫描间隔（秒）
	VerifyEnabled bool         `yaml:"verify_enabled"` // 是否启用文件校验
	MaxRetries    int          `yaml:"max_retries"`    // 最大重试次数
}

// SyncConfig 同步配置结构
type SyncConfig struct {
	Name            string         `yaml:"name"`             // 任务名称
	SourceDir       string         `yaml:"source_dir"`       // 源目录
	BackupDir       string         `yaml:"backup_dir"`       // 备份目录
	FileExtensions  []string       `yaml:"file_extensions"`  // 文件后缀
	ModifiedEnabled bool           `yaml:"modified_enabled"` // 是否启用最近修改时间过滤
	ModifiedMinutes int            `yaml:"modified_minutes"` // 修改时间范围（分钟）
	BackupEnabled   bool           `yaml:"backup_enabled"`   // 是否启用备份
	Targets         []TargetConfig `yaml:"targets"`          // 目标服务器列表
}

// TargetConfig 目标服务器配置
type TargetConfig struct {
	IP        string `yaml:"ip"`         // 服务器IP
	Port      int    `yaml:"port"`       // 端口
	Username  string `yaml:"username"`   // 用户名
	Password  string `yaml:"password"`   // 密码
	TargetDir string `yaml:"target_dir"` // 目标目录
}

// FailedFile 记录校验失败的文件信息
type FailedFile struct {
	FilePath    string
	Target      TargetConfig
	RetryCount  int
	LastError   error
	LastAttempt time.Time
}

// SFTPSync SFTP同步结构体
type SFTPSync struct {
	config      *Config
	clients     map[string]*sftp.Client // 新增：每个目标服务器只创建一个连接
	logger      *log.Logger
	failedFiles map[string]*FailedFile // 记录校验失败的文件
	dirCache    map[string]bool        // 目录存在性缓存
}

// NewSFTPSync 创建新的SFTP同步实例
func NewSFTPSync(configPath string) (*SFTPSync, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	// 创建日志文件
	logFile, err := os.OpenFile("sftp_sync.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("创建日志文件失败: %v", err)
	}

	logger := log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)
	return &SFTPSync{
		config:      config,
		clients:     make(map[string]*sftp.Client), // 新增
		logger:      logger,
		failedFiles: make(map[string]*FailedFile),
		dirCache:    make(map[string]bool),
	}, nil
}

// loadConfig 加载配置文件
func loadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 设置默认扫描间隔为5秒
	if config.ScanInterval <= 0 {
		config.ScanInterval = 5
	}

	return &config, nil
}

// connect 建立SFTP连接（复用）
func (s *SFTPSync) connect(target TargetConfig) (*sftp.Client, error) {
	key := fmt.Sprintf("%s:%d", target.IP, target.Port)
	if client, ok := s.clients[key]; ok {
		return client, nil
	}
	sshConfig := &ssh.ClientConfig{
		User: target.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(target.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	addr := fmt.Sprintf("%s:%d", target.IP, target.Port)
	sshClient, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("SSH连接失败: %v", err)
	}
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, fmt.Errorf("SFTP客户端创建失败: %v", err)
	}
	s.clients[key] = client
	return client, nil
}

// disconnectAll 关闭所有SFTP连接
func (s *SFTPSync) disconnectAll() {
	for _, client := range s.clients {
		client.Close()
	}
	s.clients = make(map[string]*sftp.Client)
}

// ensureDir 确保远程目录存在，使用缓存优化
func (s *SFTPSync) ensureDir(client *sftp.Client, path string) error {
	// 检查缓存
	if s.dirCache[path] {
		return nil
	}

	// 检查目录是否已存在
	if _, err := client.Stat(path); err == nil {
		s.dirCache[path] = true
		return nil
	}

	// 创建目录
	if err := client.MkdirAll(path); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	s.dirCache[path] = true
	s.logger.Printf("已创建目录: %s", path)
	return nil
}

// getFileMD5 计算文件的MD5值
func getFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// verifyFile 验证文件是否一致
func (s *SFTPSync) verifyFile(client *sftp.Client, localPath, remotePath string) (bool, error) {
	// 计算本地文件的MD5
	localMD5, err := getFileMD5(localPath)
	if err != nil {
		return false, fmt.Errorf("计算本地文件MD5失败: %v", err)
	}

	// 在源目录下创建tmp目录
	tmpDir := filepath.Join(filepath.Dir(localPath), "tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return false, fmt.Errorf("创建临时目录失败: %v", err)
	}

	// 下载远程文件到临时文件
	tempFile, err := os.CreateTemp(tmpDir, "sftp_verify_")
	if err != nil {
		return false, fmt.Errorf("创建临时文件失败: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	remoteFile, err := client.Open(remotePath)
	if err != nil {
		return false, fmt.Errorf("打开远程文件失败: %v", err)
	}
	defer remoteFile.Close()

	if _, err := io.Copy(tempFile, remoteFile); err != nil {
		return false, fmt.Errorf("下载远程文件失败: %v", err)
	}

	// 计算远程文件的MD5
	remoteMD5, err := getFileMD5(tempFile.Name())
	if err != nil {
		return false, fmt.Errorf("计算远程文件MD5失败: %v", err)
	}

	// 校验成功后立即删除临时文件
	if err := os.Remove(tempFile.Name()); err != nil {
		s.logger.Printf("删除临时文件失败: %v", err)
	}

	return localMD5 == remoteMD5, nil
}

// getRecentFiles 获取指定时间范围内修改的文件
func (s *SFTPSync) getRecentFiles(sourceDir string, fileExtensions []string, modifiedEnabled bool, modifiedMinutes int) ([]string, error) {
	var recentFiles []string
	now := time.Now()
	modifiedDuration := time.Duration(modifiedMinutes) * time.Minute

	// 只读取源目录下的文件，不遍历子目录
	files, err := os.ReadDir(sourceDir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(sourceDir, file.Name())
			for _, ext := range fileExtensions {
				if filepath.Ext(filePath) == ext {
					if !modifiedEnabled {
						recentFiles = append(recentFiles, filePath)
					} else {
						info, err := file.Info()
						if err != nil {
							continue
						}
						if now.Sub(info.ModTime()) <= modifiedDuration {
							recentFiles = append(recentFiles, filePath)
						}
					}
					break
				}
			}
		}
	}

	return recentFiles, nil
}

// isFileInUse 检查文件是否正在被写入
func isFileInUse(filePath string) (bool, error) {
	// Linux-specific implementation using lsof
	cmd := exec.Command("lsof", filePath)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// lsof returns 1 when file is not open by any process
			if exitErr.ExitCode() == 1 {
				return false, nil
			}
		}
		return false, err
	}
	// lsof returns 0 when file is open by at least one process
	return true, nil
}

// syncFiles 同步文件
func (s *SFTPSync) syncFiles() error {
	s.processFailedFiles()
	for _, syncConfig := range s.config.SyncConfigs {
		s.logger.Printf("开始同步任务: %s", syncConfig.Name)
		if syncConfig.BackupEnabled {
			if err := os.MkdirAll(syncConfig.BackupDir, 0755); err != nil {
				return fmt.Errorf("创建备份目录失败: %v", err)
			}
		}
		files, err := s.getRecentFiles(syncConfig.SourceDir, syncConfig.FileExtensions, syncConfig.ModifiedEnabled, syncConfig.ModifiedMinutes)
		if err != nil {
			return fmt.Errorf("获取文件列表失败: %v", err)
		}
		for _, target := range syncConfig.Targets {
			client, err := s.connect(target)
			if err != nil {
				s.logger.Printf("连接失败: %v", err)
				continue
			}
			for _, filePath := range files {
				// 检查文件是否正在被写入
				inUse, err := isFileInUse(filePath)
				if err != nil {
					s.logger.Printf("检查文件状态失败: %v", err)
					continue
				}
				if inUse {
					s.logger.Printf("文件正在被写入，跳过: %s", filePath)
					continue
				}
				relPath, err := filepath.Rel(syncConfig.SourceDir, filePath)
				if err != nil {
					s.logger.Printf("获取相对路径失败: %v", err)
					continue
				}
				targetPath := filepath.Join(target.TargetDir, relPath)
				targetDir := filepath.Dir(targetPath)
				// 确保目标目录存在
				if err := s.ensureDir(client, targetDir); err != nil {
					s.logger.Printf("确保目录存在失败: %v", err)
					continue
				}
				// 上传文件
				sourceFile, err := os.Open(filePath)
				if err != nil {
					s.logger.Printf("打开源文件失败: %v", err)
					continue
				}
				defer sourceFile.Close()
				targetFile, err := client.Create(targetPath)
				if err != nil {
					s.logger.Printf("创建目标文件失败: %v", err)
					continue
				}
				defer targetFile.Close()
				if _, err := io.Copy(targetFile, sourceFile); err != nil {
					s.logger.Printf("复制文件失败: %v", err)
					continue
				}
				s.logger.Printf("已上传: %s -> %s@%s:%s", filePath, target.Username, target.IP, targetPath)
				// 验证文件
				if s.config.VerifyEnabled {
					matches, err := s.verifyFile(client, filePath, targetPath)
					if err != nil {
						s.logger.Printf("文件校验失败: %v", err)
						s.recordFailedFile(filePath, target, err)
						continue
					}
					if matches {
						s.logger.Printf("文件校验成功: %s", filePath)
						delete(s.failedFiles, filePath)
					} else {
						s.logger.Printf("文件校验失败: %s 与远程文件不一致", filePath)
						s.recordFailedFile(filePath, target, fmt.Errorf("文件校验失败：MD5不匹配"))
					}
				}
				if syncConfig.BackupEnabled {
					backupPath := filepath.Join(syncConfig.BackupDir, relPath)
					backupDir := filepath.Dir(backupPath)
					if err := os.MkdirAll(backupDir, 0755); err != nil {
						s.logger.Printf("创建备份目录失败: %v", err)
						continue
					}
					if err := os.Rename(filePath, backupPath); err != nil {
						s.logger.Printf("移动文件到备份目录失败: %v", err)
						continue
					}
					s.logger.Printf("已备份: %s -> %s", filePath, backupPath)
				}
			}
		}
	}
	return nil
}

// processFailedFiles 处理之前校验失败的文件
func (s *SFTPSync) processFailedFiles() {
	for filePath, failedFile := range s.failedFiles {
		// 检查是否达到最大重试次数
		if failedFile.RetryCount >= s.config.MaxRetries {
			s.logger.Printf("文件 %s 已达到最大重试次数 %d，跳过", filePath, s.config.MaxRetries)
			delete(s.failedFiles, filePath)
			continue
		}

		// 尝试重新同步
		s.logger.Printf("重试同步文件: %s (第 %d 次尝试)", filePath, failedFile.RetryCount+1)

		client, err := s.connect(failedFile.Target)
		if err != nil {
			s.logger.Printf("连接失败: %v", err)
			continue
		}
		defer client.Close()

		// 重新上传文件
		if err := s.retrySyncFile(filePath, failedFile); err != nil {
			s.logger.Printf("重试同步失败: %v", err)
			failedFile.RetryCount++
			failedFile.LastError = err
			failedFile.LastAttempt = time.Now()
		} else {
			// 同步成功，从失败列表中移除
			delete(s.failedFiles, filePath)
		}
	}
}

// recordFailedFile 记录校验失败的文件
func (s *SFTPSync) recordFailedFile(filePath string, target TargetConfig, err error) {
	failedFile := &FailedFile{
		FilePath:    filePath,
		Target:      target,
		RetryCount:  0,
		LastError:   err,
		LastAttempt: time.Now(),
	}
	s.failedFiles[filePath] = failedFile
}

// retrySyncFile 重试同步文件
func (s *SFTPSync) retrySyncFile(filePath string, failedFile *FailedFile) error {
	relPath, err := filepath.Rel(failedFile.Target.TargetDir, filePath)
	if err != nil {
		return fmt.Errorf("获取相对路径失败: %v", err)
	}

	targetPath := filepath.Join(failedFile.Target.TargetDir, relPath)
	targetDir := filepath.Dir(targetPath)

	// 确保目标目录存在
	if err := s.clients[targetPath].MkdirAll(targetDir); err != nil {
		return fmt.Errorf("创建目标目录失败: %v", err)
	}

	// 上传文件
	sourceFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("打开源文件失败: %v", err)
	}
	defer sourceFile.Close()

	targetFile, err := s.clients[targetPath].Create(targetPath)
	if err != nil {
		return fmt.Errorf("创建目标文件失败: %v", err)
	}
	defer targetFile.Close()

	if _, err := io.Copy(targetFile, sourceFile); err != nil {
		return fmt.Errorf("复制文件失败: %v", err)
	}

	// 验证文件
	if s.config.VerifyEnabled {
		matches, err := s.verifyFile(s.clients[targetPath], filePath, targetPath)
		if err != nil {
			return fmt.Errorf("文件校验失败: %v", err)
		}
		if !matches {
			return fmt.Errorf("文件校验失败：MD5不匹配")
		}
	}

	return nil
}

func main() {
	// 解析命令行参数
	configPath := flag.String("config", "config.yaml", "配置文件路径")
	flag.Parse()

	sync, err := NewSFTPSync(*configPath)
	if err != nil {
		fmt.Printf("初始化失败: %v\n", err)
		return
	}

	// 创建定时器
	ticker := time.NewTicker(time.Duration(sync.config.ScanInterval) * time.Second)
	defer ticker.Stop()

	sync.logger.Printf("SFTP同步服务启动，扫描间隔: %d秒", sync.config.ScanInterval)
	if sync.config.VerifyEnabled {
		sync.logger.Printf("文件校验功能已启用")
	}

	// 立即执行一次同步
	if err := sync.syncFiles(); err != nil {
		sync.logger.Printf("首次同步失败: %v", err)
	}

	// 定时执行同步
	for range ticker.C {
		if err := sync.syncFiles(); err != nil {
			sync.logger.Printf("同步失败: %v", err)
		}
	}

	defer sync.disconnectAll()
}
