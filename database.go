package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// initDB 初始化数据库
func initDB() error {
	// 确保数据目录存在
	dataDir := "/data"
	// 在非容器环境下（如 WSL 直接运行）可能需要调整路径，但这里保持与原逻辑一致
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

		// 插入一些示例数据
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

// validateTableStructure 验证表结构
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

// getDevices 从数据库获取所有设备
func getDevices() ([]Device, error) {
	rows, err := db.Query("SELECT id, name, mac, broadcast, port, description, created_at FROM devices ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		err := rows.Scan(&d.ID, &d.Name, &d.MAC, &d.Broadcast, &d.Port, &d.Description, &d.CreatedAt)
		if err != nil {
			continue
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// addDevice 向数据库添加设备
func addDevice(d Device) error {
	_, err := db.Exec("INSERT INTO devices (name, mac, broadcast, port, description) VALUES (?, ?, ?, ?, ?)",
		d.Name, d.MAC, d.Broadcast, d.Port, d.Description)
	return err
}

// deleteDevice 从数据库删除设备
func deleteDevice(id int) error {
	_, err := db.Exec("DELETE FROM devices WHERE id = ?", id)
	return err
}
