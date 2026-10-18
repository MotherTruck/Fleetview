-- Maintenance windows for scheduled patch deployment (deployment.rs's
-- queue_scheduled_patch): on top of the existing interval_hours cadence,
-- optionally restrict *when* within that cadence a deploy is allowed to
-- actually fire -- e.g. "every 168 hours, but only Sunday 02:00-04:00
-- UTC". NULL in either column means "no restriction" (every day / all
-- hours), preserving the existing always-on behavior for schedules that
-- don't set a window.
ALTER TABLE patch_schedules ADD COLUMN window_days VARCHAR(20) NULL;
ALTER TABLE patch_schedules ADD COLUMN window_start_hour SMALLINT NULL;
ALTER TABLE patch_schedules ADD COLUMN window_end_hour SMALLINT NULL;
