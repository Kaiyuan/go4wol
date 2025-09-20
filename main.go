package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Device 设备结构体
type Device struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	MAC         string `json:"mac"`
	Broadcast   string `json:"broadcast"`
	Port        int    `json:"port"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

// WOLRequest WOL请求结构体
type WOLRequest struct {
	MAC       string `json:"mac"`
	Broadcast string `json:"broadcast,omitempty"`
	Port      int    `json:"port,omitempty"`
}

// WOLResponse WOL响应结构体
type WOLResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	MAC     string `json:"mac"`
}

// LoginRequest 登录请求结构体
type LoginRequest struct {
	Password string `json:"password"`
}

// LoginResponse 登录响应结构体
type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

var db *sql.DB
var adminPassword string
var validTokens = make(map[string]bool)

// 初始化数据库
func initDB() error {
	// 确保数据目录存在
	dataDir := "/data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("failed to create data directory: %v", err)
		}
	}

	// 数据库文件路径
	dbPath := "/data/devices.db"

	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// 测试连接
	if err = db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	// 创建设备表
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		mac TEXT NOT NULL UNIQUE,
		broadcast TEXT DEFAULT '255.255.255.255',
		port INTEGER DEFAULT 9,
		description TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create table: %v", err)
	}

	log.Printf("Database initialized successfully at %s", dbPath)
	return nil
}

// 生成简单的token
func generateToken(password string) string {
	hash := sha256.Sum256([]byte(password + time.Now().String()))
	return hex.EncodeToString(hash[:])[:32]
}

// 验证token
func validateToken(token string) bool {
	return validTokens[token]
}

// 验证MAC地址格式
func isValidMAC(mac string) bool {
	re := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	return re.MatchString(mac)
}

// 标准化MAC地址格式
func normalizeMAC(mac string) string {
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, "-", ":")
	return mac
}

// 解析MAC地址为字节数组
func parseMAC(mac string) ([]byte, error) {
	mac = normalizeMAC(mac)

	if !isValidMAC(mac) {
		return nil, fmt.Errorf("invalid MAC address format: %s", mac)
	}

	parts := strings.Split(mac, ":")
	macBytes := make([]byte, 6)

	for i, part := range parts {
		var b byte
		_, err := fmt.Sscanf(part, "%02X", &b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse MAC address: %v", err)
		}
		macBytes[i] = b
	}

	return macBytes, nil
}

// 创建WOL魔术包
func createWOLPacket(macBytes []byte) []byte {
	packet := make([]byte, 102)

	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}

	for i := 0; i < 16; i++ {
		for j := 0; j < 6; j++ {
			packet[6+i*6+j] = macBytes[j]
		}
	}

	return packet
}

// 发送WOL包
func sendWOLPacket(macAddress, broadcastIP string, port int) error {
	macBytes, err := parseMAC(macAddress)
	if err != nil {
		return err
	}

	packet := createWOLPacket(macBytes)

	if broadcastIP == "" {
		broadcastIP = "255.255.255.255"
	}
	if port == 0 {
		port = 9
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", broadcastIP, port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send WOL packet: %v", err)
	}

	log.Printf("WOL packet sent to MAC: %s via %s:%d", macAddress, broadcastIP, port)
	return nil
}

// 中间件：验证认证
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" || !validateToken(strings.TrimPrefix(token, "Bearer ")) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
			return
		}
		next(w, r)
	}
}

// 登录处理器
func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Method not allowed"})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Invalid request"})
		return
	}

	if req.Password != adminPassword {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Invalid password"})
		return
	}

	token := generateToken(req.Password)
	validTokens[token] = true

	json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Login successful",
		Token:   token,
	})
}

// WOL处理器
func wolHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		response := WOLResponse{
			Success: false,
			Message: "Method not allowed. Use POST.",
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(response)
		return
	}

	var req WOLRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		response := WOLResponse{
			Success: false,
			Message: "Invalid JSON format",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	if req.MAC == "" {
		response := WOLResponse{
			Success: false,
			Message: "MAC address is required",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	err = sendWOLPacket(req.MAC, req.Broadcast, req.Port)
	if err != nil {
		response := WOLResponse{
			Success: false,
			Message: err.Error(),
			MAC:     req.MAC,
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := WOLResponse{
		Success: true,
		Message: "WOL packet sent successfully",
		MAC:     normalizeMAC(req.MAC),
	}
	json.NewEncoder(w).Encode(response)
}

// 获取设备列表
func getDevicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query("SELECT id, name, mac, broadcast, port, description, created_at FROM devices ORDER BY name")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		err := rows.Scan(&device.ID, &device.Name, &device.MAC, &device.Broadcast, &device.Port, &device.Description, &device.CreatedAt)
		if err != nil {
			continue
		}
		devices = append(devices, device)
	}

	json.NewEncoder(w).Encode(devices)
}

// 添加设备
func addDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	var device Device
	if err := json.NewDecoder(r.Body).Decode(&device); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	if device.Name == "" || device.MAC == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Name and MAC are required"})
		return
	}

	if !isValidMAC(device.MAC) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid MAC address format"})
		return
	}

	device.MAC = normalizeMAC(device.MAC)
	if device.Broadcast == "" {
		device.Broadcast = "255.255.255.255"
	}
	if device.Port == 0 {
		device.Port = 9
	}

	_, err := db.Exec("INSERT INTO devices (name, mac, broadcast, port, description) VALUES (?, ?, ?, ?, ?)",
		device.Name, device.MAC, device.Broadcast, device.Port, device.Description)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to add device"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Device added successfully"})
}

// 删除设备
func deleteDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ID is required"})
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid ID"})
		return
	}

	_, err = db.Exec("DELETE FROM devices WHERE id = ?", id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to delete device"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Device deleted successfully"})
}

// 健康检查处理器
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "Go4WOL Service",
	}
	json.NewEncoder(w).Encode(response)
}

// PWA前端页面
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Go4WOL - Wake on LAN</title>
    <link rel="manifest" href="/manifest.json">
    <link rel="icon" type="image/png" href="/icon-192.png">
    <meta name="theme-color" content="#2196F3">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg,rgb(202, 228, 248),rgb(240, 250, 252)); color:rgb(61, 61, 61); padding: 20px; border-radius: 12px; margin-bottom: 20px; text-align: center; }
        .login-form, .main-content { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        div[class*="hidden"], .hidden { display: none; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 500; }
        input, select, textarea { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 16px; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: #2196F3; }
        .btn { background: #2196F3; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 16px; margin-right: 10px; margin-bottom: 10px; }
        .btn:hover { background: #1976D2; }
        .btn-danger { background: #f44336; }
        .btn-danger:hover { background: #d32f2f; }
        .btn-success { background: #4CAF50; }
        .btn-success:hover { background: #45a049; }
        .device-list { margin-top: 20px; }
        .device-item { background: white; border: 2px solid #ddd; border-radius: 12px; padding: 15px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: all 0.3s; }
        .device-item:hover { border-color: #2196F3; transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .device-info h3 { color: #333; margin-bottom: 5px; }
        .device-info p { color: #666; font-size: 14px; }
        .device-actions button { margin-left: 10px; padding: 8px 16px; font-size: 14px; }
        .toast { position: fixed; top: 20px; right: 20px; padding: 15px 20px; border-radius: 8px; color: white; z-index: 1000; }
        .toast.success { background: #4CAF50; }
        .toast.error { background: #f44336; }
        .modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 1001; }
        .modal-content { background: white; padding: 30px; border-radius: 12px; width: 90%; max-width: 500px; }
        .modal-header { margin-bottom: 20px; }
        .modal-header h2 { color: #333; }
        .close { float: right; font-size: 28px; cursor: pointer; color: #aaa; }
        .close:hover { color: #333; }
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .device-item { flex-direction: column; align-items: flex-start; }
            .device-actions { margin-top: 10px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕹️ Go4WOL</h1>
            <p>Wake on LAN Service</p>
        </div>

        <!-- 登录界面 -->
        <div id="loginForm" class="login-form">
            <h2>🔐 登录验证</h2>
            <div class="form-group">
                <label for="password">密码:</label>
                <input type="password" id="password" placeholder="请输入管理密码">
            </div>
            <button class="btn" onclick="login()">登录</button>
        </div>

        <!-- 主界面 -->
        <div id="mainContent" class="main-content hidden">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>设备管理</h2>
                <div>
                    <button class="btn" onclick="showAddDeviceModal()">➕ 添加设备</button>
                    <button class="btn btn-danger" onclick="logout()">🚪 退出登录</button>
                </div>
            </div>
            
            <div id="deviceList" class="device-list"></div>
        </div>
    </div>

    <!-- 添加设备模态框 -->
    <div id="addDeviceModal" class="modal hidden">
        <div class="modal-content">
            <div class="modal-header">
                <span class="close" onclick="hideAddDeviceModal()">&times;</span>
                <h2>添加新设备</h2>
            </div>
            <div class="form-group">
                <label for="deviceName">设备名称:</label>
                <input type="text" id="deviceName" placeholder="如：办公电脑">
            </div>
            <div class="form-group">
                <label for="deviceMAC">MAC地址:</label>
                <input type="text" id="deviceMAC" placeholder="如：AA:BB:CC:DD:EE:FF">
            </div>
            <div class="form-group">
                <label for="deviceBroadcast">广播地址:</label>
                <input type="text" id="deviceBroadcast" placeholder="默认：255.255.255.255">
            </div>
            <div class="form-group">
                <label for="devicePort">端口:</label>
                <input type="number" id="devicePort" placeholder="默认：9">
            </div>
            <div class="form-group">
                <label for="deviceDescription">描述:</label>
                <textarea id="deviceDescription" placeholder="设备描述信息（可选）"></textarea>
            </div>
            <button class="btn btn-success" onclick="addDevice()">保存设备</button>
            <button class="btn" onclick="hideAddDeviceModal()">取消</button>
        </div>
    </div>

    <script>
        let authToken = localStorage.getItem('go4wol_token');
        
        // 页面加载时检查登录状态
        window.onload = function() {
            if (authToken) {
                showMainContent();
                loadDevices();
            }
            
            // 注册Service Worker
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.register('/sw.js');
            }
        };

        function login() {
            const password = document.getElementById('password').value;
            if (!password) {
                showToast('请输入密码', 'error');
                return;
            }

            fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    authToken = data.token;
                    localStorage.setItem('go4wol_token', authToken);
                    showMainContent();
                    loadDevices();
                    showToast('登录成功', 'success');
                } else {
                    showToast(data.message || '登录失败', 'error');
                }
            })
            .catch(error => {
                showToast('网络错误', 'error');
                console.error('Error:', error);
            });
        }

        function logout() {
            localStorage.removeItem('go4wol_token');
            authToken = null;
            document.getElementById('mainContent').classList.add('hidden');
            document.getElementById('loginForm').classList.remove('hidden');
            document.getElementById('password').value = '';
        }

        function showMainContent() {
            document.getElementById('loginForm').classList.add('hidden');
            document.getElementById('mainContent').classList.remove('hidden');
        }

        function loadDevices() {
            fetch('/api/devices', {
                headers: { 'Authorization': 'Bearer ' + authToken }
            })
            .then(response => response.json())
            .then(devices => {
                const deviceList = document.getElementById('deviceList');
                if (!devices || devices.length === 0) {
                    deviceList.innerHTML = '<p style="text-align: center; color: #666;">暂无设备，请先添加设备</p>';
                    return;
                }

                // 清空设备列表
                deviceList.innerHTML = '';
                
                // 为每个设备创建DOM元素
                devices.forEach(device => {
                    const deviceItem = document.createElement('div');
                    deviceItem.className = 'device-item';
                    
                    // 设置点击事件
                    deviceItem.addEventListener('click', () => {
                        wakeDevice(device.mac, device.broadcast, device.port);
                    });
                    
                    // 创建设备信息
                    const deviceInfo = document.createElement('div');
					deviceInfo.className = 'device-info';
					deviceInfo.innerHTML =
						"<h3>🖥️ " + escapeHtml(device.name) + "</h3>" +
						"<p><strong>MAC:</strong> " + escapeHtml(device.mac) + "</p>" +
						"<p><strong>广播:</strong> " + escapeHtml(device.broadcast) + ":" + device.port + "</p>" +
						(device.description ? "<p><strong>描述:</strong> " + escapeHtml(device.description) + "</p>" : "");
                    
                    // 创建操作按钮
                    const deviceActions = document.createElement('div');
                    deviceActions.className = 'device-actions';
                    
                    const wakeButton = document.createElement('button');
                    wakeButton.className = 'btn btn-success';
                    wakeButton.textContent = '⚡ 唤醒';
                    wakeButton.addEventListener('click', (e) => {
                        e.stopPropagation();
                        wakeDevice(device.mac, device.broadcast, device.port);
                    });
                    
                    const deleteButton = document.createElement('button');
                    deleteButton.className = 'btn btn-danger';
                    deleteButton.textContent = '🗑️ 删除';
                    deleteButton.addEventListener('click', (e) => {
                        e.stopPropagation();
                        deleteDevice(device.id);
                    });
                    
                    deviceActions.appendChild(wakeButton);
                    deviceActions.appendChild(deleteButton);
                    
                    deviceItem.appendChild(deviceInfo);
                    deviceItem.appendChild(deviceActions);
                    deviceList.appendChild(deviceItem);
                });
            })
            .catch(error => {
                showToast('加载设备失败', 'error');
                console.error('Error:', error);
            });
        }

        // HTML转义函数，防止XSS攻击
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function wakeDevice(mac, broadcast, port) {
            const payload = { mac };
            if (broadcast && broadcast !== '255.255.255.255') payload.broadcast = broadcast;
            if (port && port !== 9) payload.port = port;

            fetch('/wol', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast('WOL包发送成功 🚀', 'success');
                } else {
                    showToast(data.message || 'WOL包发送失败', 'error');
                }
            })
            .catch(error => {
                showToast('网络错误', 'error');
                console.error('Error:', error);
            });
        }

        function showAddDeviceModal() {
            document.getElementById('addDeviceModal').classList.remove('hidden');
        }

        function hideAddDeviceModal() {
            document.getElementById('addDeviceModal').classList.add('hidden');
            // 清空表单
            ['deviceName', 'deviceMAC', 'deviceBroadcast', 'devicePort', 'deviceDescription'].forEach(id => {
                document.getElementById(id).value = '';
            });
        }

        function addDevice() {
            const name = document.getElementById('deviceName').value.trim();
            const mac = document.getElementById('deviceMAC').value.trim();
            const broadcast = document.getElementById('deviceBroadcast').value.trim() || '255.255.255.255';
            const portValue = document.getElementById('devicePort').value.trim();
            const port = portValue ? parseInt(portValue) : 9;
            const description = document.getElementById('deviceDescription').value.trim();

            if (!name || !mac) {
                showToast('设备名称和MAC地址不能为空', 'error');
                return;
            }

            // 验证MAC地址格式
            const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
            if (!macRegex.test(mac)) {
                showToast("请输入有效的MAC地址格式（如：AA:BB:CC:DD:EE:FF）", "error");
                return;
            }

            // 验证端口号
            if (isNaN(port) || port < 1 || port > 65535) {
                showToast('请输入有效的端口号（1-65535）', 'error');
                return;
            }

            const deviceData = {
                name: name,
                mac: mac.toUpperCase().replace(/-/g, ':'), // 标准化MAC地址格式
                broadcast: broadcast,
                port: port,
                description: description
            };

            fetch('/api/devices', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + authToken
                },
                body: JSON.stringify(deviceData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    showToast('设备添加成功', 'success');
                    hideAddDeviceModal();
                    loadDevices();
                } else {
                    showToast(data.error || '添加设备失败', 'error');
                }
            })
            .catch(error => {
                showToast('网络错误', 'error');
                console.error('Error:', error);
            });
        }

        function deleteDevice(deviceId) {
            if (!confirm('确定要删除这个设备吗？')) return;

			fetch("/api/devices?id=" + encodeURIComponent(deviceId), {
				method: 'DELETE',
				headers: { 'Authorization': 'Bearer ' + authToken }
			})
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    showToast('设备删除成功', 'success');
                    loadDevices();
                } else {
                    showToast(data.error || '删除设备失败', 'error');
                }
            })
            .catch(error => {
                showToast('网络错误', 'error');
                console.error('Error:', error);
            });
        }

        function showToast(message, type) {
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.textContent = message;
            document.body.appendChild(toast);

            setTimeout(() => {
                document.body.removeChild(toast);
            }, 3000);
        }

        // 回车键登录
        document.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !document.getElementById('loginForm').classList.contains('hidden')) {
                login();
            }
        });
    </script>
</body>
</html>`
	fmt.Fprint(w, html)
}

// PWA Manifest
func manifestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	manifest := `{
		"name": "Go4WOL - Wake on LAN",
		"short_name": "Go4WOL",
		"description": "Wake on LAN Service",
		"start_url": "/",
		"display": "standalone",
		"background_color": "#2196F3",
		"theme_color": "#2196F3",
		"icons": [
			{
				"src": "/icon-192.png",
				"sizes": "192x192",
				"type": "image/png"
			},
			{
				"src": "/icon-512.png",
				"sizes": "512x512",
				"type": "image/png"
			}
		]
	}`
	fmt.Fprint(w, manifest)
}

// Service Worker
func serviceWorkerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	sw := `
const CACHE_NAME = 'go4wol-v1';
const urlsToCache = [
	'/',
	'/manifest.json'
];

self.addEventListener('install', function(event) {
	event.waitUntil(
		caches.open(CACHE_NAME)
			.then(function(cache) {
				return cache.addAll(urlsToCache);
			})
	);
});

self.addEventListener('fetch', function(event) {
	event.respondWith(
		caches.match(event.request)
			.then(function(response) {
				if (response) {
					return response;
				}
				return fetch(event.request);
			}
		)
	);
});
`
	fmt.Fprint(w, sw)
}

// 生成简单的图标（SVG格式）
func iconHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	svg := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 912 1274.93">
  <defs>
    <style>
      .cls-1 {
        fill: none;
      }

      .cls-2 {
        isolation: isolate;
      }

      .cls-3 {
        fill: #273263;
      }

      .cls-4 {
        clip-path: url(#clippath);
      }
    </style>
    <clipPath id="clippath">
      <path class="cls-1" d="M826.71,397.68l-105.91,110.08c-22.62,102.52-101.39,183.95-202.42,210.39l-105.9,110.06c11.46,1.03,23.06,1.56,34.79,1.56,211.32,0,382.64-171.31,382.64-382.64,0-16.76-1.1-33.27-3.19-49.46ZM280.81,672.45c-28.82-21.34-53.42-48.06-72.27-78.7l-73.54.19,40.27-79.6c-5.3-21.53-8.13-44.02-8.13-67.19,0-116.81,71.5-216.9,173.12-258.94l61.2-120.97C211.73,89.86,64.63,251.32,64.63,447.14c0,133.15,68.01,250.41,171.19,318.95l44.99-93.64ZM676.58,286.24c10.61,15.09,19.75,31.28,27.26,48.35l108.92-.97c-16.79-54.11-45.25-103.08-82.45-143.96l-53.72,96.58ZM553.73,383.65L749.64,1.63h-236.73L227.95,557.3h193.82l-195.91,382.03L747.55,383.65h-193.82Z"/>
    </clipPath>
  </defs>
  <g id="_椭圆_1_拷贝_2" data-name="椭圆 1 拷贝 2" class="cls-2">
    <g id="_椭圆_1_拷贝_2-2" data-name="椭圆 1 拷贝 2">
      <path class="cls-3" d="M699.58,304.24c10.61,15.09,19.75,31.28,27.26,48.35l108.92-.97c-16.79-54.11-45.25-103.08-82.45-143.96l-53.72,96.58ZM303.81,690.45c-28.82-21.34-53.42-48.06-72.27-78.7l-73.54.19,40.27-79.6c-5.3-21.53-8.13-44.02-8.13-67.19,0-116.81,71.5-216.9,173.12-258.94l61.2-120.97C234.73,107.86,87.63,269.32,87.63,465.14c0,133.15,68.01,250.41,171.19,318.95l44.99-93.64ZM849.71,415.68l-105.91,110.08c-22.62,102.52-101.39,183.95-202.42,210.39l-105.9,110.06c11.46,1.03,23.06,1.56,34.79,1.56,211.32,0,382.64-171.31,382.64-382.64,0-16.76-1.1-33.27-3.19-49.46ZM576.73,401.65L772.64,19.63h-236.73L250.95,575.3h193.82l-195.91,382.03L770.55,401.65h-193.82Z"/>
    </g>
  </g>
  <g id="_椭圆_1_拷贝_形状_1_形状_2" data-name="椭圆 1 拷贝 + 形状 1 + 形状 2" class="cls-2">
    <g class="cls-4">
      <image id="_椭圆_1_拷贝_形状_1_形状_2_图像" data-name="椭圆 1 拷贝 + 形状 1 + 形状 2 图像" width="766" height="939" transform="translate(64 .93)" xlink:href="data:image/png;base64,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"/>
    </g>
  </g>
</svg>`
	fmt.Fprint(w, svg)
}

func main() {
	// 获取环境变量
	port := os.Getenv("PORT")
	if port == "" {
		port = "52133"
	}

	adminPassword = os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "admin123"
		log.Println("Warning: Using default password 'admin123'. Set ADMIN_PASSWORD environment variable for security.")
	}

	// 初始化数据库
	if err := initDB(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	// 路由设置
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/manifest.json", manifestHandler)
	http.HandleFunc("/sw.js", serviceWorkerHandler)
	http.HandleFunc("/icon-192.png", iconHandler)
	http.HandleFunc("/icon-512.png", iconHandler)

	// API路由
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/devices", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getDevicesHandler(w, r)
		case http.MethodPost:
			addDeviceHandler(w, r)
		case http.MethodDelete:
			deleteDeviceHandler(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	// 保持原有的WOL API不变
	http.HandleFunc("/wol", wolHandler)
	http.HandleFunc("/health", healthHandler)

	log.Printf("Go4WOL Service starting on port %s", port)
	log.Printf("Admin password: %s", adminPassword)
	log.Printf("Database path: /data/devices.db")
	log.Printf("Endpoints:")
	log.Printf("  GET  / - PWA Frontend")
	log.Printf("  POST /api/login - Login")
	log.Printf("  GET  /api/devices - Get devices (auth required)")
	log.Printf("  POST /api/devices - Add device (auth required)")
	log.Printf("  DEL  /api/devices - Delete device (auth required)")
	log.Printf("  POST /wol - Send WOL packet (original API)")
	log.Printf("  GET  /health - Health check")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
