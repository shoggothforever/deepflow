START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET sub_view_params="{\"DATABASE\":\"\",\"include_history\":\"true\",\"PROM_SQL\":\"delta(min(deepflow_system__deepflow_agent_monitor__create_time)by(host)[1m:])\",\"interval\":60,\"metric\":\"process_start\",\"time_tag\":\"toi\"}" WHERE name="进程启动";


-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.38';
-- modify end

COMMIT;
