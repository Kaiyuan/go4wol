package main

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
