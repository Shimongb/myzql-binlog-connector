-- ============================================================
-- 1. Users & Grants
-- ============================================================
CREATE USER IF NOT EXISTS 'myzql_repl_user'@'%'
  IDENTIFIED WITH caching_sha2_password BY 'ReplPass2025';

GRANT REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'myzql_repl_user'@'%';
GRANT SELECT ON *.* TO 'myzql_repl_user'@'%';
FLUSH PRIVILEGES;

-- ============================================================
-- 2. Schema
-- ============================================================
CREATE DATABASE IF NOT EXISTS testdb;
USE testdb;

-- Table 1: orders  (covers INT, BIGINT, VARCHAR, DECIMAL, DATETIME, ENUM, TEXT, BOOLEAN, TIMESTAMP)
CREATE TABLE orders (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_uuid      CHAR(36)        NOT NULL,
    customer_name   VARCHAR(120)    NOT NULL,
    email           VARCHAR(255)    NOT NULL,
    status          ENUM('pending','processing','shipped','delivered','cancelled') NOT NULL DEFAULT 'pending',
    item_count      INT UNSIGNED    NOT NULL DEFAULT 1,
    total_amount    DECIMAL(12,2)   NOT NULL DEFAULT 0.00,
    currency        CHAR(3)         NOT NULL DEFAULT 'USD',
    notes           TEXT            NULL,
    is_priority     BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      TIMESTAMP(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    INDEX idx_status (status),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table 2: sensor_readings  (covers FLOAT, DOUBLE, TINYINT, SMALLINT, DATE, TIME, BLOB, JSON, BIT)
CREATE TABLE sensor_readings (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    sensor_id       SMALLINT UNSIGNED NOT NULL,
    reading_date    DATE            NOT NULL,
    reading_time    TIME(3)         NOT NULL,
    temperature_c   FLOAT           NOT NULL,
    humidity_pct    DOUBLE          NOT NULL,
    battery_level   TINYINT UNSIGNED NOT NULL,   -- 0-255
    is_alert        BIT(1)          NOT NULL DEFAULT b'0',
    raw_payload     BLOB            NULL,
    metadata        JSON            NULL,
    INDEX idx_sensor_date (sensor_id, reading_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ============================================================
-- 3. Seed data  (~5 000 rows per table via recursive CTEs)
--    This runs inside the binlog so your connector will see
--    the INSERT events immediately.
-- ============================================================
SET SESSION cte_max_recursion_depth = 10000;

-- Seed orders (5 000 rows)
INSERT INTO orders (order_uuid, customer_name, email, status, item_count, total_amount, currency, notes, is_priority, created_at)
WITH RECURSIVE seq AS (
    SELECT 1 AS n
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 5000
)
SELECT
    UUID(),
    CONCAT('Customer_', LPAD(n, 5, '0')),
    CONCAT('customer', n, '@example.com'),
    ELT(1 + (n % 5), 'pending','processing','shipped','delivered','cancelled'),
    1 + (n % 20),
    ROUND(9.99 + (n % 500) * 3.17, 2),
    ELT(1 + (n % 3), 'USD', 'EUR', 'GBP'),
    IF(n % 7 = 0, CONCAT('Note for order ', n), NULL),
    (n % 10 = 0),
    DATE_ADD('2025-01-01', INTERVAL (n * 37) SECOND)
FROM seq;

-- Seed sensor_readings (5 000 rows)
INSERT INTO sensor_readings (sensor_id, reading_date, reading_time, temperature_c, humidity_pct, battery_level, is_alert, raw_payload, metadata)
WITH RECURSIVE seq AS (
    SELECT 1 AS n
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 5000
)
SELECT
    1 + (n % 50),                                                   -- 50 distinct sensors
    DATE_ADD('2025-06-01', INTERVAL (n DIV 48) DAY),               -- ~48 readings/day
    SEC_TO_TIME((n % 86400)),                                       -- spread across 24h
    ROUND(-10.0 + (n % 450) * 0.1, 1),                            -- -10 .. 35 C
    ROUND(20.0 + (n % 600) * 0.1, 1),                             -- 20 .. 80 %
    LEAST(255, 50 + (n % 206)),                                     -- battery 50-255
    IF(n % 100 = 0, b'1', b'0'),                                   -- 1% alert rate
    IF(n % 13 = 0, UNHEX(SHA2(CONCAT('payload-', n), 256)), NULL), -- occasional BLOB
    IF(n % 5 = 0, JSON_OBJECT('fw', CONCAT('v1.', n % 10), 'rssi', -30 - (n % 70)), NULL)
FROM seq;

-- ============================================================
-- 4. DDL Mid-Run Tests
--    These DDL changes happen AFTER the seed data, so the
--    binlog connector will see them mid-stream and must update
--    its schema cache accordingly.
-- ============================================================

-- 4a. ALTER TABLE: Add a column at the end
ALTER TABLE orders ADD COLUMN shipping_method VARCHAR(50) DEFAULT 'standard';

-- 4b. Insert some rows with the new column
INSERT INTO orders (order_uuid, customer_name, email, status, item_count, total_amount, shipping_method)
VALUES (UUID(), 'DDL_Test_Customer_1', 'ddl1@test.com', 'pending', 3, 99.99, 'express');

-- 4c. ALTER TABLE: Add a column with FIRST position
ALTER TABLE orders ADD COLUMN region CHAR(2) DEFAULT 'US' FIRST;

-- 4d. Insert with new column layout
INSERT INTO orders (region, order_uuid, customer_name, email, status, item_count, total_amount, shipping_method)
VALUES ('EU', UUID(), 'DDL_Test_Customer_2', 'ddl2@test.com', 'processing', 1, 49.99, 'priority');

-- 4e. ALTER TABLE: Add column AFTER a specific column
ALTER TABLE orders ADD COLUMN discount_pct DECIMAL(5,2) DEFAULT 0.00 AFTER total_amount;

-- 4f. ALTER TABLE: Rename a column
ALTER TABLE orders RENAME COLUMN customer_name TO full_name;

-- 4g. ALTER TABLE: Change ENUM values (add new value)
ALTER TABLE orders MODIFY COLUMN status ENUM('pending','processing','shipped','delivered','cancelled','returned') NOT NULL DEFAULT 'pending';

-- 4h. Insert with the new enum value
INSERT INTO orders (region, order_uuid, full_name, email, status, item_count, total_amount, discount_pct, shipping_method)
VALUES ('US', UUID(), 'DDL_Test_Customer_3', 'ddl3@test.com', 'returned', 2, 75.00, 10.50, 'standard');

-- 4i. ALTER TABLE: Drop a column
ALTER TABLE orders DROP COLUMN notes;

-- 4j. ALTER TABLE: Change column type and position
ALTER TABLE sensor_readings CHANGE COLUMN battery_level battery_pct TINYINT UNSIGNED NOT NULL AFTER humidity_pct;

-- 4k. Insert into modified sensor_readings
INSERT INTO sensor_readings (sensor_id, reading_date, reading_time, temperature_c, humidity_pct, battery_pct, is_alert, metadata)
VALUES (99, '2026-03-28', '12:00:00.000', 22.5, 55.0, 200, b'0', JSON_OBJECT('test', 'ddl_mid_run'));

-- 4l. CREATE TABLE mid-stream (new table the connector hasn't seen)
CREATE TABLE audit_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    action ENUM('create','update','delete','login','logout') NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id BIGINT UNSIGNED NOT NULL,
    actor VARCHAR(100) NOT NULL,
    details JSON NULL,
    tags SET('system','user','admin','api') NOT NULL DEFAULT '',
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4m. Insert into the new table
INSERT INTO audit_log (action, entity_type, entity_id, actor, details, tags)
VALUES
    ('create', 'order', 1, 'admin_user', JSON_OBJECT('note', 'DDL test order'), 'admin,api'),
    ('update', 'order', 1, 'system_bot', JSON_OBJECT('field', 'status', 'old', 'pending', 'new', 'shipped'), 'system'),
    ('login', 'user', 42, 'john_doe', NULL, 'user'),
    ('delete', 'sensor', 99, 'admin_user', JSON_OBJECT('reason', 'decommissioned'), 'admin');

-- 4n. ALTER the new table to test DDL on freshly created table
ALTER TABLE audit_log ADD COLUMN ip_address VARCHAR(45) NULL AFTER actor;

INSERT INTO audit_log (action, entity_type, entity_id, actor, ip_address, details, tags)
VALUES ('logout', 'user', 42, 'john_doe', '192.168.1.100', NULL, 'user');

-- 4o. RENAME TABLE test
RENAME TABLE audit_log TO event_log;

INSERT INTO event_log (action, entity_type, entity_id, actor, ip_address, tags)
VALUES ('create', 'config', 1, 'deploy_bot', '10.0.0.1', 'system,api');
