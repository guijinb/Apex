-- Apex Passkey (WebAuthn) 支持
-- 参考：W3C WebAuthn Level 2

-- 用户的 Passkey 凭证（一个用户可绑定多个设备）
CREATE TABLE IF NOT EXISTS passkeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  credential_id TEXT NOT NULL UNIQUE,       -- base64url 编码的 credential ID
  public_key TEXT NOT NULL,                 -- base64url 编码的 COSE public key
  counter INTEGER NOT NULL DEFAULT 0,       -- 签名计数器（防重放）
  transports TEXT,                          -- 逗号分隔：usb,nfc,ble,internal,hybrid
  device_name TEXT,                         -- 用户可读的设备名（如 "iPhone 15"）
  aaguid TEXT,                              -- 认证器型号 UUID
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys(credential_id);

-- 一次性 challenge 存储（WebAuthn 注册/登录流程用）
CREATE TABLE IF NOT EXISTS passkey_challenges (
  id TEXT PRIMARY KEY,                      -- 随机 ID（发给前端）
  challenge TEXT NOT NULL,                  -- base64url 编码的 32 字节
  type TEXT NOT NULL,                       -- 'registration' | 'authentication'
  user_id INTEGER,                          -- 注册时必填；登录时为 NULL
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires ON passkey_challenges(expires_at);
