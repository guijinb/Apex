CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_action_created
  ON rate_limits(ip, action, created_at);
