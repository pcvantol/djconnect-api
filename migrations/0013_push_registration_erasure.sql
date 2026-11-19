-- Older rows have no authoritative first deactivation timestamp.
DELETE FROM registrations WHERE disabled = 1 OR invalid = 1;

-- Also cover workers already in flight during a rollout or code rollback.
CREATE TRIGGER registrations_erase_on_deactivation
AFTER UPDATE OF disabled, invalid ON registrations
WHEN NEW.disabled = 1 OR NEW.invalid = 1
BEGIN
	DELETE FROM registrations WHERE id = NEW.id;
END;

CREATE INDEX idx_relay_events_created ON relay_events (created_at);
CREATE INDEX idx_push_delivery_failures_event ON push_delivery_failures (relay_event_id);
CREATE INDEX idx_registrations_last_success ON registrations (last_success_at)
	WHERE last_success_at IS NOT NULL;
CREATE INDEX idx_registrations_last_error ON registrations (updated_at)
	WHERE last_error_code IS NOT NULL;
