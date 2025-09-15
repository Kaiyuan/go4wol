package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// WOLRequest 请求结构体
type WOLRequest struct {
	MAC       string `json:"mac"`
	Broadcast string `json:"broadcast,omitempty"` // 可选的广播地址
	Port      int    `json:"port,omitempty"`      // 可选的端口，默认9
}

// WOLResponse 响应结构体
type WOLResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	MAC     string `json:"mac"`
}

// 验证MAC地址格式
func isValidMAC(mac string) bool {
	// 支持常见的MAC地址格式：XX:XX:XX:XX:XX:XX 或 XX-XX-XX-XX-XX-XX
	re := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	return re.MatchString(mac)
}

// 标准化MAC地址格式（转换为XX:XX:XX:XX:XX:XX格式）
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
	// WOL包结构：6字节0xFF + 16次重复的MAC地址
	packet := make([]byte, 102) // 6 + 16*6 = 102字节

	// 前6个字节填充0xFF
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}

	// 后面16次重复MAC地址
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

	// 默认广播地址和端口
	if broadcastIP == "" {
		broadcastIP = "255.255.255.255"
	}
	if port == 0 {
		port = 9
	}

	// 创建UDP连接
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", broadcastIP, port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	// 发送WOL包
	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send WOL packet: %v", err)
	}

	log.Printf("WOL packet sent to MAC: %s via %s:%d", macAddress, broadcastIP, port)
	return nil
}

// HTTP处理器：发送WOL包
func wolHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// 处理OPTIONS请求（CORS预检）
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

	// 验证MAC地址
	if req.MAC == "" {
		response := WOLResponse{
			Success: false,
			Message: "MAC address is required",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// 发送WOL包
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

	// 成功响应
	response := WOLResponse{
		Success: true,
		Message: "WOL packet sent successfully",
		MAC:     normalizeMAC(req.MAC),
	}
	json.NewEncoder(w).Encode(response)
}

// 健康检查处理器
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "WOL Service",
	}
	json.NewEncoder(w).Encode(response)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "52133"
	}

	// 路由设置
	http.HandleFunc("/wol", wolHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := `<!DOCTYPE html>
<html>
<head>
    <title>WOL Service</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>Wake-on-LAN Service</h1>
    <p>这是一个WOL服务，用于通过网络唤醒设备。</p>
    <h2>使用方法：</h2>
    <ul>
        <li>POST /wol - 发送WOL包</li>
        <li>GET /health - 健康检查</li>
    </ul>
    <h3>请求示例：</h3>
    <pre>
POST /wol
Content-Type: application/json

{
    "mac": "AA:BB:CC:DD:EE:FF",
    "broadcast": "192.168.1.255",
    "port": 9
}
    </pre>
</body>
</html>`
		fmt.Fprint(w, html)
	})

	log.Printf("WOL Service starting on port %s", port)
	log.Printf("Endpoints:")
	log.Printf("  POST /wol - Send WOL packet")
	log.Printf("  GET /health - Health check")
	log.Printf("  GET / - Service info")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
