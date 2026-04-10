package main

import (
	"log"
	"net/http"
	"os"
)

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
		log.Fatalf("Database initialization failed: %v", err)
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

	// API 路由
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/verify", authMiddleware(verifyHandler))
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
	http.HandleFunc("/api/db-status", authMiddleware(dbStatusHandler))

	// WOL API (保持原有路径兼容)
	http.HandleFunc("/wol", wolHandler)
	http.HandleFunc("/health", healthHandler)

	log.Printf("Go4WOL Service starting on port %s", port)
	log.Printf("Admin password: %s", adminPassword)
	log.Printf("Database path: /data/devices.db")
	
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
