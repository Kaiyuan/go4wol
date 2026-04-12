package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// API 处理器

// loginHandler 登录处理器
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

	token, err := GenerateToken(req.Password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(LoginResponse{Success: false, Message: "Invalid password"})
		return
	}

	json.NewEncoder(w).Encode(LoginResponse{
		Success: true,
		Message: "Login successful",
		Token:   token,
	})
}

// verifyHandler 验证 Token 有效性
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"valid": true})
}

// wolHandler WOL处理器
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
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(WOLResponse{Success: false, Message: "Method not allowed"})
		return
	}

	var req WOLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(WOLResponse{Success: false, Message: "Invalid JSON"})
		return
	}

	if req.MAC == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(WOLResponse{Success: false, Message: "MAC is required"})
		return
	}

	if err := sendWOLPacket(req.MAC, req.Broadcast, req.Port); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(WOLResponse{Success: false, Message: err.Error(), MAC: req.MAC})
		return
	}

	json.NewEncoder(w).Encode(WOLResponse{Success: true, Message: "WOL packet sent", MAC: normalizeMAC(req.MAC)})
}

// getDevicesHandler 获取设备列表
func getDevicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	devices, err := getDevices()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if devices == nil {
		devices = []Device{}
	}
	json.NewEncoder(w).Encode(devices)
}

// addDeviceHandler 添加设备
func addDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var d Device
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}
	if d.Name == "" || d.MAC == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Name and MAC required"})
		return
	}
	if !isValidMAC(d.MAC) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid MAC"})
		return
	}
	d.MAC = normalizeMAC(d.MAC)
	if d.Broadcast == "" {
		d.Broadcast = "255.255.255.255"
	}
	if d.Port == 0 {
		d.Port = 9
	}
	if err := addDevice(d); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "Device added"})
}

// deleteDeviceHandler 删除设备
func deleteDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)
	if err := deleteDevice(id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "Device deleted"})
}

// healthHandler 健康检查
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	res := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	}
	json.NewEncoder(w).Encode(res)
}

// dbStatusHandler 数据库状态
func dbStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := map[string]interface{}{"connected": db != nil}
	json.NewEncoder(w).Encode(status)
}

// 前端处理器

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

func manifestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, manifestJSON)
}

func serviceWorkerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	fmt.Fprint(w, swJS)
}

func iconHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	fmt.Fprint(w, iconSVG)
}

// 静态内容

const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Go4WOL - 远程唤醒</title>
    <link rel="manifest" href="/manifest.json">
    <link rel="icon" type="image/svg+xml" href="/icon-192.png">
    <meta name="theme-color" content="#1a1a2e">
    <style>
        :root {
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --bg: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --text: #f8fafc;
            --text-dim: #94a3b8;
            --accent: #10b981;
            --danger: #ef4444;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            background: var(--bg); 
            color: var(--text);
            min-height: 100vh;
            background-image: radial-gradient(circle at top right, #1e1b4b, transparent), radial-gradient(circle at bottom left, #0f172a, transparent);
        }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .header { 
            padding: 40px 20px; 
            text-align: center;
            animation: fadeInDown 0.8s ease-out;
        }
        .header svg { filter: drop-shadow(0 0 10px var(--primary)); }
        
        .card { 
            background: var(--card-bg); 
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 30px; 
            border-radius: 20px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            margin-bottom: 20px;
        }
        .hidden { display: none !important; }
        
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 500; color: var(--text-dim); }
        input, select, textarea { 
            width: 100%; 
            padding: 14px; 
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px; 
            font-size: 16px; 
            color: white;
            transition: all 0.3s;
        }
        input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.2); }
        
        .btn { 
            background: var(--primary); 
            color: white; 
            border: none; 
            padding: 14px 28px; 
            border-radius: 12px; 
            cursor: pointer; 
            font-size: 16px; 
            font-weight: 600;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .btn:hover { background: var(--primary-hover); transform: translateY(-2px); }
        .btn:active { transform: translateY(0); }
        .btn-danger { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }
        .btn-danger:hover { background: var(--danger); color: white; }
        .btn-ghost { background: transparent; color: var(--text-dim); }
        .btn-ghost:hover { color: white; background: rgba(255,255,255,0.05); }

        .device-item { 
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px; 
            padding: 20px; 
            margin-bottom: 12px; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            transition: all 0.3s;
            animation: slideInUp 0.5s ease-out;
        }
        .device-item:hover { 
            background: rgba(255, 255, 255, 0.07);
            border-color: var(--primary);
            transform: scale(1.01);
        }
        .device-info h3 { color: var(--text); margin-bottom: 4px; font-size: 18px; }
        .device-info p { color: var(--text-dim); font-size: 13px; font-family: monospace; }
        
        .device-actions { display: flex; gap: 8px; }
        .icon-btn { 
            width: 40px; 
            height: 40px; 
            border-radius: 10px; 
            display: flex; 
            align-items: center; 
            justify-content: center;
            border: none;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-wake { background: var(--accent); color: white; }
        .btn-wake:hover { filter: brightness(1.2); }
        .btn-del { background: rgba(239, 68, 68, 0.1); color: var(--danger); }
        .btn-del:hover { background: var(--danger); color: white; }

        .toast { 
            position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); 
            padding: 12px 24px; border-radius: 12px; color: white; z-index: 2000; 
            box-shadow: 0 10px 20px rgba(0,0,0,0.3); animation: bounceUp 0.4s;
        }
        .toast.success { background: var(--accent); }
        .toast.error { background: var(--danger); }

        .modal { 
            position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
            background: rgba(0,0,0,0.8); backdrop-filter: blur(8px);
            display: flex; justify-content: center; align-items: center; z-index: 1500; 
        }

        @keyframes fadeInDown { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes slideInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes bounceUp { from { transform: translate(-50%, 50px); opacity: 0; } to { transform: translate(-50%, 0); opacity: 1; } }

        @media (max-width: 600px) {
            .device-item { flex-direction: column; align-items: stretch; gap: 15px; }
            .device-actions { justify-content: flex-end; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <svg id="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 289.14 50" width="200px" height="35px" fill="currentColor">
                <path d="M26.9,23.31h21.95c-.5,5.45-2.22,14.2-8.11,20.09-5.31,5.31-11.69,6.6-17.43,6.6s-11.69-1.29-16.79-6.24c-3.37-3.23-6.53-8.39-6.53-16.43C0,18.72,3.59,11.76,8.11,7.39,11.98,3.66,18.15,0,27.62,0c3.8,0,8.32.65,12.7,3.37,2.65,1.65,5.24,4.16,7.17,7.46l-8.39,4.81c-1.29-2.37-3.01-4.02-4.81-5.09-2.3-1.43-4.88-2.08-7.75-2.08-5.52,0-9.33,2.3-11.69,4.66-3.3,3.3-5.24,8.54-5.24,13.7,0,5.67,2.44,9.04,4.16,10.76,3.23,3.23,7.17,3.95,10.26,3.95,2.73,0,6.53-.43,9.76-3.23,2.15-1.87,3.66-4.59,4.45-6.96h-12.34l1-8.03Z"/><path d="M85.22,21.31c2.01,2.08,4.02,5.45,4.02,10.33,0,3.95-1.22,8.9-5.52,13.06-4.09,3.87-8.75,5.24-14.28,5.24-4.45,0-8.61-.93-11.98-4.3-2.3-2.22-4.09-5.67-4.09-10.54s2.22-9.9,5.38-12.98c2.51-2.44,6.96-5.24,14.2-5.24,6.1,0,9.9,2.08,12.27,4.45ZM77.11,39.45c1.79-1.79,2.94-4.52,2.94-6.96,0-1.94-.79-4.3-2.3-5.74-1.44-1.36-3.59-2.15-5.67-2.15-2.44,0-4.88.93-6.6,2.51-2.15,2.01-3.08,4.95-3.08,7.39,0,1.87.79,4.09,2.15,5.45,1.44,1.44,3.73,2.22,5.74,2.22,2.37,0,4.95-.86,6.81-2.73Z"/><path d="M125.53,32.42h5.6l-.93,7.46h-5.6l-1.08,9.04h-8.75l1.08-9.04h-23.39l.57-4.16L121.01,1.08h8.39l-3.87,31.35ZM116.78,32.42l2.22-18.51-14.56,18.51h12.34Z"/><path d="M154.15,48.92h-6.6L136.64,1.08h9.76l6.67,32.57L168.85,1.08h5.17l6.96,32.57L196.47,1.08h10.04l-24.03,47.85h-6.6l-6.74-30.34-14.99,30.34Z"/><path d="M252.06,6.17c3.59,3.44,6.31,8.82,6.31,15.93,0,7.6-2.87,15.14-7.68,20.09-3.8,3.95-10.26,7.82-19.94,7.82s-14.78-3.8-17.58-6.67c-3.95-4.02-6.31-9.83-6.31-15.85,0-7.89,3.3-15.28,8.25-19.94,5.02-4.73,12.48-7.53,20.37-7.53,6.82,0,12.77,2.51,16.57,6.17ZM243.02,36.8c3.44-3.37,5.67-8.61,5.67-13.99,0-4.3-1.58-7.82-3.8-10.11-2.08-2.15-5.67-4.16-10.9-4.16s-9.18,2.01-11.91,4.59c-3.66,3.44-5.52,8.46-5.52,13.63s1.94,8.46,3.8,10.4c2.58,2.73,6.46,4.38,10.9,4.38,4.81,0,8.9-1.94,11.77-4.73Z"/><path d="M279.24,1.08l-4.88,39.81h14.78l-1,8.03h-24.1l5.88-47.85h9.33Z"/>
            </svg>
            <p style="margin-top: 10px; color: var(--text-dim);">Wake on LAN 远程开机服务</p>
        </div>

        <!-- 登录界面 -->
        <div id="loginForm" class="card">
            <h2 style="margin-bottom: 25px;">🔒 登录验证</h2>
            <div class="form-group">
                <input type="password" id="password" placeholder="请输入管理密码">
            </div>
            <button class="btn" style="width: 100%; justify-content: center;" onclick="login()">立即登录</button>
        </div>

        <!-- 主界面 -->
        <div id="mainContent" class="hidden">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px;">
                <h2>🖥️ 设备面板</h2>
                <div class="device-actions">
                    <button class="btn btn-ghost" onclick="showAddDeviceModal()">➕</button>
                    <button class="btn btn-ghost" onclick="logout()">🚪</button>
                </div>
            </div>
            <div id="deviceList"></div>
        </div>
    </div>

    <!-- 添加设备模态框 -->
    <div id="addDeviceModal" class="modal hidden">
        <div class="card" style="width: 90%; max-width: 500px;">
            <h2 style="margin-bottom: 20px;">添加新设备</h2>
            <div class="form-group">
                <label>设备名称</label>
                <input type="text" id="deviceName" placeholder="例如：我的电脑">
            </div>
            <div class="form-group">
                <label>MAC 地址</label>
                <input type="text" id="deviceMAC" placeholder="AA:BB:CC:DD:EE:FF">
            </div>
            <div class="form-group">
                <label>广播地址</label>
                <input type="text" id="deviceBroadcast" value="255.255.255.255">
            </div>
            <div class="form-group">
                <label>端口</label>
                <input type="number" id="devicePort" value="9">
            </div>
            <div style="display: flex; gap: 10px; margin-top: 30px;">
                <button class="btn" style="flex: 1; justify-content: center;" onclick="addDevice()">保存</button>
                <button class="btn btn-ghost" style="flex: 1;" onclick="hideAddDeviceModal()">取消</button>
            </div>
        </div>
    </div>

    <script>
        let authToken = localStorage.getItem('go4wol_token');
        
        window.onload = async function() {
            if (authToken) {
                const isValid = await verifyToken();
                if (isValid) {
                    showMainContent();
                    loadDevices();
                } else {
                    logout();
                }
            }
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.register('/sw.js');
            }
        };

        async function verifyToken() {
            try {
                const res = await fetch('/api/verify', {
                    headers: { 'Authorization': 'Bearer ' + authToken }
                });
                return res.ok;
            } catch (e) {
                return false;
            }
        }

        async function fetchWithAuth(url, options = {}) {
            options.headers = options.headers || {};
            options.headers['Authorization'] = 'Bearer ' + authToken;
            const response = await fetch(url, options);
            if (response.status === 401) {
                logout();
                throw new Error('Unauthorized');
            }
            return response;
        }

        function login() {
            const password = document.getElementById('password').value;
            if (!password) return showToast('请输入密码', 'error');

            fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    authToken = data.token;
                    localStorage.setItem('go4wol_token', authToken);
                    showMainContent();
                    loadDevices();
                    showToast('欢迎回来', 'success');
                } else {
                    showToast(data.message || '密码错误', 'error');
                }
            })
            .catch(() => showToast('网络错误', 'error'));
        }

        function logout() {
            localStorage.removeItem('go4wol_token');
            authToken = null;
            document.getElementById('mainContent').classList.add('hidden');
            document.getElementById('loginForm').classList.remove('hidden');
        }

        function showMainContent() {
            document.getElementById('loginForm').classList.add('hidden');
            document.getElementById('mainContent').classList.remove('hidden');
        }

        async function loadDevices() {
            try {
                const res = await fetchWithAuth('/api/devices');
                const devices = await res.json();
                const list = document.getElementById('deviceList');
                list.innerHTML = devices.length ? '' : '<p style="text-align: center; color: var(--text-dim);">暂无设备</p>';
                devices.forEach(d => {
                    const item = document.createElement('div');
                    item.className = 'device-item';
                    item.innerHTML = ` + "`" + `
                        <div class="device-info">
                            <h3>${escapeHtml(d.name)}</h3>
                            <p>${d.mac}</p>
                        </div>
                        <div class="device-actions">
                            <button class="icon-btn btn-wake" onclick="wakeDevice('${d.mac}', '${d.broadcast}', ${d.port})">启动</button>
                            <button class="icon-btn btn-del" onclick="deleteDevice(${d.id})">删除</button>
                        </div>
                    ` + "`" + `;
                    list.appendChild(item);
                });
            } catch (e) {}
        }

        function wakeDevice(mac, broadcast, port) {
            fetchWithAuth('/wol', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mac, broadcast, port })
            })
            .then(() => showToast('唤醒指令已发送', 'success'))
            .catch(() => showToast('发送失败', 'error'));
        }

        function addDevice() {
            const data = {
                name: document.getElementById('deviceName').value,
                mac: document.getElementById('deviceMAC').value,
                broadcast: document.getElementById('deviceBroadcast').value,
                port: parseInt(document.getElementById('devicePort').value)
            };
            fetchWithAuth('/api/devices', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(res => res.json())
            .then(data => {
                if(data.message) {
                    showToast('添加成功', 'success');
                    hideAddDeviceModal();
                    loadDevices();
                } else showToast(data.error, 'error');
            });
        }

        function deleteDevice(id) {
            if (!confirm('确认删除?')) return;
            fetchWithAuth('/api/devices?id=' + id, { method: 'DELETE' })
            .then(() => loadDevices());
        }

        function showAddDeviceModal() { document.getElementById('addDeviceModal').classList.remove('hidden'); }
        function hideAddDeviceModal() { document.getElementById('addDeviceModal').classList.add('hidden'); }
        function showToast(msg, type) {
            const t = document.createElement('div');
            t.className = 'toast ' + type;
            t.textContent = msg;
            document.body.appendChild(t);
            setTimeout(() => t.remove(), 3000);
        }
        function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
    </script>
</body>
</html>`

const manifestJSON = `{"name":"Go4WOL","short_name":"Go4WOL","display":"standalone","start_url":"/","background_color":"#0f172a","theme_color":"#1a1a2e","icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/svg+xml"}]}`

const swJS = `self.addEventListener('fetch', function(event) { event.respondWith(fetch(event.request)); });`

const iconSVG = `<?xml version="1.0" encoding="UTF-8"?><svg id="uuid-826e361e-d40a-4dbe-aff0-ed97bb858d29" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 512 512" width="192" height="192"><defs><linearGradient id="uuid-bdcbd5fc-2b2c-408d-952f-e0b21354247e" x1="256" y1="0" x2="256" y2="512" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#effff3"/><stop offset="1" stop-color="#e7e1da"/></linearGradient><clipPath id="uuid-027fd979-4d4c-4a6e-b0fa-dddff0f81035"><path d="M369.96,238.62l-33.78,35.12c-7.21,32.7-32.35,58.68-64.57,67.12l-33.78,35.11c3.65.33,7.35.49,11.1.49,67.41,0,122.07-54.65,122.07-122.07,0-5.34-.35-10.61-1.02-15.77h-.02ZM195.81,326.27c-9.19-6.81-17.03-15.33-23.05-25.11l-23.46.06,12.84-25.39c-1.69-6.87-2.6-14.04-2.6-21.44,0-37.26,22.81-69.19,55.22-82.61l19.52-38.58c-60.5,7.21-107.43,58.71-107.43,121.19,0,42.48,21.69,79.88,54.61,101.75l14.36-29.87h-.02ZM322.08,203.07c3.38,4.82,6.3,9.98,8.69,15.42l34.74-.3c-5.36-17.26-14.44-32.89-26.3-45.92l-17.13,30.82v-.02ZM282.89,234.14l62.49-121.86h-75.52l-90.9,177.26h61.82l-62.49,121.88,166.43-177.27h-61.82,0Z" style="fill:none;"/></clipPath></defs><rect width="512" height="512" style="fill:url(#uuid-bdcbd5fc-2b2c-408d-952f-e0b21354247e);"/><g id="uuid-a49a1f5c-c81e-4079-b1ae-e3eafd2ba15c"><g id="uuid-7e55e500-2281-4f67-ad8f-24dc33069cc9" style="isolation:isolate;"><g id="uuid-3ab134bd-3a1a-4962-9cdd-e30087b526c5" style="isolation:isolate; opacity:.1;"><path d="M329.41,208.81c3.38,4.82,6.3,9.98,8.69,15.42l34.74-.3c-5.36-17.26-14.44-32.89-26.3-45.92l-17.13,30.82h0v-.02ZM203.15,332.01c-9.19-6.81-17.03-15.33-23.05-25.11l-23.46.06,12.84-25.39c-1.69-6.87-2.6-14.04-2.6-21.44,0-37.26,22.81-69.19,55.22-82.61l19.52-38.58c-60.5,7.21-107.43,58.71-107.43,121.19,0,42.48,21.69,79.88,54.61,101.75l14.36-29.87h-.02ZM377.3,244.36l-33.78,35.12c-7.21,32.7-32.35,58.68-64.57,67.12l-33.78,35.11c3.65.33,7.35.49,11.1.49,67.41,0,122.07-54.65,122.07-122.07,0-5.34-.35-10.61-1.02-15.77h-.02ZM290.22,239.88l62.49-121.86h-75.52l-90.9,177.26h61.82l-62.49,121.88,166.43-177.27h-61.82Z" style="fill:#273263;"/></g></g><g id="uuid-b7cb697a-6e6e-4c95-8898-522f140e4dcf" style="isolation:isolate;"><g style="clip-path:url(#uuid-027fd979-4d4c-4a6e-b0fa-dddff0f81035);"><rect x="102.09" y="112.28" width="306.25" height="304.87" style="fill:#6a86ff;"/><polygon points="349.43 185.33 324.87 210.85 319.19 202.35 338.81 169.03 349.43 185.33" style="fill:#fff; isolation:isolate; opacity:.1;"/><polygon points="343.78 120 349.67 110.95 267.08 110.95 175.64 290.84 192.3 290.84 280.21 126.38 343.78 120" style="fill:#fff; isolation:isolate; opacity:.1;"/><polygon points="284.1 231.65 279.49 240.85 339.75 240.85 348.25 233.07 284.1 231.65" style="fill:#fff; isolation:isolate; opacity:.1;"/><polygon points="150.83 297.22 146.93 307.53 180.1 306.9 175.29 297.22 150.83 297.22" style="fill:#fff; isolation:isolate; opacity:.1;"/><polygon points="228.45 292.26 279.49 253.26 178.28 417.2 170.68 413.12 228.45 292.26" style="fill:#fff; isolation:isolate; opacity:.1;"/><path d="M369.96,238.61l-28.09,40.88s-9.22,49.97-66.29,68.76l-33.96,40.77-9.65-12.57,133.52-141.27,4.45,3.43h.02Z" style="fill:#fff; isolation:isolate; opacity:.1;"/><path d="M234.3,133.21l-4.79,9.83s-106.69,19.49-87.9,156.31l-2.22,13.92s-77.89-157.64,94.9-180.06Z" style="fill:#fff; isolation:isolate; opacity:.1;"/></g></g></g></svg>`
