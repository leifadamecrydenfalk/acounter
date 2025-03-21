-- Create enum types
CREATE TYPE alert_severity AS ENUM ('info', 'warning', 'error', 'critical');
CREATE TYPE notification_channel AS ENUM ('email', 'slack', 'telegram', 'webhook');

-- Alerts table
CREATE TABLE alerts (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    condition TEXT NOT NULL,
    severity alert_severity NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- Subscriptions table
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY,
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    channel_type notification_channel NOT NULL,
    target TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- Alert history table
CREATE TABLE alert_history (
    id UUID PRIMARY KEY,
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    triggered_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL,
    resolved_at TIMESTAMPTZ
);

-- Create indexes
CREATE INDEX idx_alerts_is_active ON alerts(is_active);
CREATE INDEX idx_subscriptions_alert_id ON subscriptions(alert_id);
CREATE INDEX idx_alert_history_alert_id ON alert_history(alert_id);
CREATE INDEX idx_alert_history_triggered_at ON alert_history(triggered_at);