-- schema.sql
-- 1) create database
CREATE DATABASE IF NOT EXISTS attack_logs_db
  CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_unicode_ci;

USE attack_logs_db;

--@block
-- 2) roles table
CREATE TABLE IF NOT EXISTS roles (
  role_id INT AUTO_INCREMENT PRIMARY KEY,
  role_name VARCHAR(50) NOT NULL UNIQUE,
  description TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--@block
-- 3) users table
CREATE TABLE IF NOT EXISTS users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL, -- store hashed password
  role_id INT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--@block
-- 4) attack_types table
CREATE TABLE IF NOT EXISTS attack_types (
  attack_id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  description TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--@block
-- 5) logs table
CREATE TABLE IF NOT EXISTS logs (
  log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  source_ip VARCHAR(45) NOT NULL, -- supports IPv4 and IPv6
  attack_id INT,
  status ENUM('Detected', 'Investigating', 'Resolved') DEFAULT 'Detected',
  details TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  created_by INT,
  INDEX idx_source_ip (source_ip),
  INDEX idx_attack_id (attack_id),
  FOREIGN KEY (attack_id) REFERENCES attack_types(attack_id) ON DELETE SET NULL,
  FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
--@block
-- 6) seed basic roles and attack types
INSERT INTO roles (role_name, description)
  VALUES ('admin', 'Full access'), ('viewer', 'Read-only');


-- Brute Force
INSERT INTO attack_types (name, description)
SELECT 'Brute Force', 'Repeated unauthorized login attempts'
WHERE NOT EXISTS (
  SELECT 1 FROM attack_types WHERE name = 'Brute Force'
);

-- DDoS
INSERT INTO attack_types (name, description)
SELECT 'DDoS', 'High-volume request flood'
WHERE NOT EXISTS (
  SELECT 1 FROM attack_types WHERE name = 'DDoS'
);

--@block
-- 7) incidents table
CREATE TABLE IF NOT EXISTS incidents (
  incident_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  source_ip VARCHAR(45) NOT NULL,
  attack_id INT,
  attempts INT NOT NULL,
  severity ENUM('low','medium','high','critical') NOT NULL,
  notes TEXT,
  created_by INT,
  CONSTRAINT fk_incident_attack FOREIGN KEY (attack_id) REFERENCES attack_types(attack_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;