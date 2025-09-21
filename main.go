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
		log.Printf("Data directory does not exist, creating: %s", dataDir)
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("failed to create data directory: %v", err)
		}
	}

	// 数据库文件路径
	dbPath := "/data/devices.db"
	dbExists := true

	// 检查数据库文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Printf("Database file does not exist, will create new one: %s", dbPath)
		dbExists = false
	}

	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// 测试连接
	if err = db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	// 创建设备表（如果不存在）
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

	// 创建索引以提高查询性能
	indexSQL := `CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);`
	_, err = db.Exec(indexSQL)
	if err != nil {
		log.Printf("Warning: failed to create index: %v", err)
	}

	if !dbExists {
		log.Printf("New database created and initialized successfully at %s", dbPath)

		// 可选：插入一些示例数据（仅在新数据库时）
		sampleDataSQL := `
		INSERT OR IGNORE INTO devices (name, mac, broadcast, port, description) VALUES 
		('示例设备', '00:00:00:00:00:00', '255.255.255.255', 9, '这是一个示例设备，您可以删除它');`

		_, err = db.Exec(sampleDataSQL)
		if err != nil {
			log.Printf("Warning: failed to insert sample data: %v", err)
		} else {
			log.Printf("Sample device data inserted")
		}
	} else {
		log.Printf("Existing database connected successfully at %s", dbPath)
	}

	// 验证表结构
	if err = validateTableStructure(); err != nil {
		return fmt.Errorf("table structure validation failed: %v", err)
	}

	return nil
}

// 验证表结构
func validateTableStructure() error {
	// 检查表是否存在以及基本结构
	var count int
	query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='devices';`
	err := db.QueryRow(query).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check table existence: %v", err)
	}

	if count == 0 {
		return fmt.Errorf("devices table does not exist")
	}

	// 检查必要的列是否存在
	columns := []string{"id", "name", "mac", "broadcast", "port", "description", "created_at"}
	for _, column := range columns {
		query := fmt.Sprintf(`SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name='%s';`, column)
		var columnCount int
		err := db.QueryRow(query).Scan(&columnCount)
		if err != nil {
			log.Printf("Warning: failed to check column %s: %v", column, err)
			continue
		}
		if columnCount == 0 {
			log.Printf("Warning: column %s does not exist in devices table", column)
		}
	}

	log.Printf("Database table structure validation completed")
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

	// 检查数据库连接
	if db == nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Database not initialized"})
		return
	}

	if err := db.Ping(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Database connection failed"})
		return
	}

	rows, err := db.Query("SELECT id, name, mac, broadcast, port, description, created_at FROM devices ORDER BY name")
	if err != nil {
		log.Printf("Database query error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Database query failed"})
		return
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		err := rows.Scan(&device.ID, &device.Name, &device.MAC, &device.Broadcast, &device.Port, &device.Description, &device.CreatedAt)
		if err != nil {
			log.Printf("Row scan error: %v", err)
			continue
		}
		devices = append(devices, device)
	}

	// 检查是否有扫描错误
	if err = rows.Err(); err != nil {
		log.Printf("Rows iteration error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Data retrieval failed"})
		return
	}

	// 如果没有设备，返回空数组而不是null
	if devices == nil {
		devices = []Device{}
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

	// 基本健康状态
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "Go4WOL Service",
		"database":  "unknown",
	}

	// 检查数据库状态
	if db != nil {
		if err := db.Ping(); err == nil {
			response["database"] = "connected"
		} else {
			response["database"] = "error"
			response["status"] = "degraded"
		}
	} else {
		response["database"] = "disconnected"
		response["status"] = "degraded"
	}

	json.NewEncoder(w).Encode(response)
}

// 数据库状态检查处理器
func dbStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}

	status := map[string]interface{}{
		"connected":    false,
		"table_exists": false,
		"device_count": 0,
		"db_path":      "/data/devices.db",
		"message":      "",
	}

	// 检查数据库连接
	if db != nil {
		if err := db.Ping(); err == nil {
			status["connected"] = true

			// 检查表是否存在
			var count int
			query := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='devices';`
			if err := db.QueryRow(query).Scan(&count); err == nil && count > 0 {
				status["table_exists"] = true

				// 获取设备数量
				var deviceCount int
				if err := db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&deviceCount); err == nil {
					status["device_count"] = deviceCount
				}
			}
		} else {
			status["message"] = "Database ping failed: " + err.Error()
		}
	} else {
		status["message"] = "Database connection is nil"
	}

	// 检查数据库文件是否存在
	if _, err := os.Stat("/data/devices.db"); os.IsNotExist(err) {
		status["message"] = "Database file does not exist"
	}

	if status["connected"].(bool) && status["table_exists"].(bool) {
		status["message"] = "Database is healthy"
	}

	json.NewEncoder(w).Encode(status)
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
    <meta name="theme-color" content="#f5f5f5">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: "Sarasa Term SC", "Helvetica Neue", Ubuntu, Helvetica, "Source Han Serif", "PingFang SC","Hiragino Sans GB", "Microsoft YaHei", "Wenquanyi Micro Hei", "WenQuanYi Zen Hei", "WenQuanYi Zen Hei", "Apple LiGothic Medium", "ST Heiti", "WenQuanYi Zen Hei Sharp", -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { color:rgb(61, 61, 61); padding: 20px; border-radius: 12px; margin-bottom: 20px; text-align: center; }
        .login-form, .main-content { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        div[class*="hidden"], .hidden { display: none; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 500; }
        input, select, textarea { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 16px; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: #605fec; }
        .btn { background: #605fec; color: white; border: none; padding: 12px 24px; border-radius: 4px; cursor: pointer; font-size: 16px; margin-right: 10px; margin-bottom: 10px; }
        .btn:hover { background: #5956aa; }
        .btn-danger { background: #ffdc3a; }
        .btn-danger:hover { background: #e6bb35; }
        .btn-success { background: #38d480; }
        .btn-success:hover { background: #2eae69; }
        .device-list { margin-top: 20px; }
        .device-item { background: white; border: 1px solid #ddd; border-radius: 12px; padding: 15px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: all 0.3s; }
        .device-item:hover { border-color: #5956aa; transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .device-info h3 { color: #333; margin-bottom: 5px; }
        .device-info p { color: #666; font-size: 14px; }
        .device-actions button { margin-left: 10px; padding: 8px 16px; font-size: 14px; }
        .toast { position: fixed; top: 20px; right: 20px; padding: 15px 20px; border-radius: 8px; color: white; z-index: 1000; }
        .toast.success { background: #38d480; }
        .toast.error { background: #e6bb35; }
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
            <h1><svg id="uuid-275bee91-c775-492c-8d2c-1c35a846a290" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 289.14 50" width="290px" height="50px"><path d="M26.9,23.31h21.95c-.5,5.45-2.22,14.2-8.11,20.09-5.31,5.31-11.69,6.6-17.43,6.6s-11.69-1.29-16.79-6.24c-3.37-3.23-6.53-8.39-6.53-16.43C0,18.72,3.59,11.76,8.11,7.39,11.98,3.66,18.15,0,27.62,0c3.8,0,8.32.65,12.7,3.37,2.65,1.65,5.24,4.16,7.17,7.46l-8.39,4.81c-1.29-2.37-3.01-4.02-4.81-5.09-2.3-1.43-4.88-2.08-7.75-2.08-5.52,0-9.33,2.3-11.69,4.66-3.3,3.3-5.24,8.54-5.24,13.7,0,5.67,2.44,9.04,4.16,10.76,3.23,3.23,7.17,3.95,10.26,3.95,2.73,0,6.53-.43,9.76-3.23,2.15-1.87,3.66-4.59,4.45-6.96h-12.34l1-8.03Z"/><path d="M85.22,21.31c2.01,2.08,4.02,5.45,4.02,10.33,0,3.95-1.22,8.9-5.52,13.06-4.09,3.87-8.75,5.24-14.28,5.24-4.45,0-8.61-.93-11.98-4.3-2.3-2.22-4.09-5.67-4.09-10.54s2.22-9.9,5.38-12.98c2.51-2.44,6.96-5.24,14.2-5.24,6.1,0,9.9,2.08,12.27,4.45ZM77.11,39.45c1.79-1.79,2.94-4.52,2.94-6.96,0-1.94-.79-4.3-2.3-5.74-1.44-1.36-3.59-2.15-5.67-2.15-2.44,0-4.88.93-6.6,2.51-2.15,2.01-3.08,4.95-3.08,7.39,0,1.87.79,4.09,2.15,5.45,1.44,1.44,3.73,2.22,5.74,2.22,2.37,0,4.95-.86,6.81-2.73Z"/><path d="M125.53,32.42h5.6l-.93,7.46h-5.6l-1.08,9.04h-8.75l1.08-9.04h-23.39l.57-4.16L121.01,1.08h8.39l-3.87,31.35ZM116.78,32.42l2.22-18.51-14.56,18.51h12.34Z"/><path d="M154.15,48.92h-6.6L136.64,1.08h9.76l6.67,32.57L168.85,1.08h5.17l6.96,32.57L196.47,1.08h10.04l-24.03,47.85h-6.6l-6.74-30.34-14.99,30.34Z"/><path d="M252.06,6.17c3.59,3.44,6.31,8.82,6.31,15.93,0,7.6-2.87,15.14-7.68,20.09-3.8,3.95-10.26,7.82-19.94,7.82s-14.78-3.8-17.58-6.67c-3.95-4.02-6.31-9.83-6.31-15.85,0-7.89,3.3-15.28,8.25-19.94,5.02-4.73,12.48-7.53,20.37-7.53,6.82,0,12.77,2.51,16.57,6.17ZM243.02,36.8c3.44-3.37,5.67-8.61,5.67-13.99,0-4.3-1.58-7.82-3.8-10.11-2.08-2.15-5.67-4.16-10.9-4.16s-9.18,2.01-11.91,4.59c-3.66,3.44-5.52,8.46-5.52,13.63s1.94,8.46,3.8,10.4c2.58,2.73,6.46,4.38,10.9,4.38,4.81,0,8.9-1.94,11.77-4.73Z"/><path d="M279.24,1.08l-4.88,39.81h14.78l-1,8.03h-24.1l5.88-47.85h9.33Z"/></svg></h1>
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
                <h2>🗒️ 设备管理</h2>
                <div>
                    <button class="btn" onclick="showAddDeviceModal()"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" width="20px" height="20px" fill="#ffffff"><!--!Font Awesome Free v7.0.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2025 Fonticons, Inc.--><path d="M352 128C352 110.3 337.7 96 320 96C302.3 96 288 110.3 288 128L288 288L128 288C110.3 288 96 302.3 96 320C96 337.7 110.3 352 128 352L288 352L288 512C288 529.7 302.3 544 320 544C337.7 544 352 529.7 352 512L352 352L512 352C529.7 352 544 337.7 544 320C544 302.3 529.7 288 512 288L352 288L352 128z"/></svg></button>
                    <button class="btn btn-danger" onclick="logout()"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" width="20px" height="20px" fill="#ffffff"><!--!Font Awesome Free v7.0.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2025 Fonticons, Inc.--><path d="M342.6 73.4C330.1 60.9 309.8 60.9 297.3 73.4L169.3 201.4C156.8 213.9 156.8 234.2 169.3 246.7C181.8 259.2 202.1 259.2 214.6 246.7L288 173.3L288 384C288 401.7 302.3 416 320 416C337.7 416 352 401.7 352 384L352 173.3L425.4 246.7C437.9 259.2 458.2 259.2 470.7 246.7C483.2 234.2 483.2 213.9 470.7 201.4L342.7 73.4zM160 416C160 398.3 145.7 384 128 384C110.3 384 96 398.3 96 416L96 480C96 533 139 576 192 576L448 576C501 576 544 533 544 480L544 416C544 398.3 529.7 384 512 384C494.3 384 480 398.3 480 416L480 480C480 497.7 465.7 512 448 512L192 512C174.3 512 160 497.7 160 480L160 416z"/></svg></button>
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
                    wakeButton.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" width="24px" height="24px" fill="#ffffff"><path d="M128 320L156.5 92C158.5 76 172.1 64 188.3 64L356.9 64C371.9 64 384 76.1 384 91.1C384 94.3 383.4 97.6 382.3 100.6L336 224L475.3 224C495.5 224 512 240.4 512 260.7C512 268.1 509.8 275.3 505.6 281.4L313.4 562.4C307.5 571 297.8 576.1 287.5 576.1L284.6 576.1C268.9 576.1 256.1 563.3 256.1 547.6C256.1 545.3 256.4 543 257 540.7L304 352L160 352C142.3 352 128 337.7 128 320z"></path></svg>';
                    wakeButton.addEventListener('click', (e) => {
                        e.stopPropagation();
                        wakeDevice(device.mac, device.broadcast, device.port);
                    });
                    
                    const deleteButton = document.createElement('button');
                    deleteButton.className = 'btn btn-danger';
                    deleteButton.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640" width="24px" height="24px" fill="#ffffff"><path d="M232.7 69.9L224 96L128 96C110.3 96 96 110.3 96 128C96 145.7 110.3 160 128 160L512 160C529.7 160 544 145.7 544 128C544 110.3 529.7 96 512 96L416 96L407.3 69.9C402.9 56.8 390.7 48 376.9 48L263.1 48C249.3 48 237.1 56.8 232.7 69.9zM512 208L128 208L149.1 531.1C150.7 556.4 171.7 576 197 576L443 576C468.3 576 489.3 556.4 490.9 531.1L512 208z"/></svg>';
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
		"background_color": "#f5f5f5",
		"theme_color": "#f5f5f5",
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
const CACHE_NAME = 'go4wol-v1.1';
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
	svg := `<svg id="go4wollogo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192" width="192" height="192"><defs><style>.st0,.st1{isolation:isolate}.st0,.st2{fill:#fff;opacity:.1}</style><clipPath id="clippath"><path d="M167.94 80.04l-21.18 22.02c-4.52 20.5-20.28 36.79-40.48 42.08L85.1 166.15c2.29.21 4.61.31 6.96.31 42.26 0 76.53-34.26 76.53-76.53 0-3.35-.22-6.65-.64-9.89zM58.76 134.99a56.382 56.382 0 0 1-14.45-15.74l-14.71.04 8.05-15.92c-1.06-4.31-1.63-8.8-1.63-13.44 0-23.36 14.3-43.38 34.62-51.79l12.24-24.19c-37.93 4.52-67.35 36.81-67.35 75.98 0 26.63 13.6 50.08 34.24 63.79l9-18.73zm79.16-77.24c2.12 3.02 3.95 6.26 5.45 9.67l21.78-.19a76.447 76.447 0 0 0-16.49-28.79l-10.74 19.32zm-24.57 19.48L152.53.83h-47.35L48.19 111.96h38.76l-39.18 76.41L152.11 77.23h-38.76z" fill="none"/></clipPath></defs><g id="sh" class="st1"><path d="M142.52 61.35c2.12 3.02 3.95 6.26 5.45 9.67l21.78-.19a76.447 76.447 0 0 0-16.49-28.79l-10.74 19.32zm-79.16 77.24a56.382 56.382 0 0 1-14.45-15.74l-14.71.04 8.05-15.92c-1.06-4.31-1.63-8.8-1.63-13.44 0-23.36 14.3-43.38 34.62-51.79l12.24-24.19c-37.93 4.52-67.35 36.81-67.35 75.98 0 26.63 13.6 50.08 34.24 63.79l9-18.73zm109.18-54.95l-21.18 22.02c-4.52 20.5-20.28 36.79-40.48 42.08L89.7 169.75c2.29.21 4.61.31 6.96.31 42.26 0 76.53-34.26 76.53-76.53 0-3.35-.22-6.65-.64-9.89zm-54.59-2.81l39.18-76.4h-47.35L52.79 115.56h38.76l-39.18 76.41L156.71 80.83h-38.76z" fill="#273263" id="logo_bg"/></g><g clip-path="url(#clippath)" id="logo"><path fill="#6a86ff" d="M0 .83h192v191.14H0z"/><path class="st2" d="M155.07 46.63l-15.4 16-3.56-5.33 12.3-20.89 6.66 10.22zM151.53 5.67L155.22 0h-51.78L46.11 112.78h10.45L111.67 9.67l39.86-4zM114.11 75.67l-2.89 5.77H149l5.33-4.88-40.22-.89zM30.56 116.78l-2.45 6.46 20.8-.39-3.02-6.07H30.56zM79.22 113.67l32-24.45L47.77 192 43 189.44l36.22-75.77zM167.94 80.03l-17.61 25.63s-5.78 31.33-41.56 43.11l-21.29 25.56-6.05-7.88 83.71-88.57 2.79 2.15z"/><path class="st0" d="M82.89 13.95l-3 6.16s-66.89 12.22-55.11 98l-1.39 8.73s-48.83-98.83 59.5-112.89z"/></g></svg>`
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

	// 初始化数据库，如果失败则尝试重建
	if err := initDB(); err != nil {
		log.Printf("Initial database initialization failed: %v", err)
		log.Println("Attempting to rebuild database...")

		// 尝试删除损坏的数据库文件并重建
		dbPath := "/data/devices.db"
		if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to remove corrupted database: %v", err)
		}

		// 再次尝试初始化
		if err := initDB(); err != nil {
			log.Fatal("Failed to initialize database after rebuild attempt:", err)
		}
		log.Println("Database successfully rebuilt")
	}

	defer func() {
		if db != nil {
			db.Close()
		}
	}()

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

	// 添加数据库状态检查端点
	http.HandleFunc("/api/db-status", authMiddleware(dbStatusHandler))

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
	log.Printf("  GET  /api/db-status - Database status (auth required)")
	log.Printf("  POST /wol - Send WOL packet (original API)")
	log.Printf("  GET  /health - Health check")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
