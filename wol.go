package main

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
)

// isValidMAC 验证MAC地址格式
func isValidMAC(mac string) bool {
	re := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	return re.MatchString(mac)
}

// normalizeMAC 标准化MAC地址格式
func normalizeMAC(mac string) string {
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, "-", ":")
	return mac
}

// parseMAC 解析MAC地址为字节数组
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

// createWOLPacket 创建WOL魔术包
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

// sendWOLPacket 发送WOL包
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
