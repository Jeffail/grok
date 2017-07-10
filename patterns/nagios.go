package patterns

// Chop Nagios log files to smithereens!
//
// A set of GROK filters to process logfiles generated by Nagios.
// While it does not, this set intends to cover all possible Nagios logs.
//
// Some more work needs to be done to cover all External Commands:
//	http://old.nagios.org/developerinfo/externalcommands/commandlist.php
//
// If you need some support on these rules please contact:
//	Jelle Smet http://smetj.net

var Nagios = map[string]string{
	"NAGIOSTIME": `\[%{NUMBER:nagios_epoch}\]`,

	//
	// Begin nagios log types
	//
	"NAGIOS_TYPE_CURRENT_SERVICE_STATE": `CURRENT SERVICE STATE`,
	"NAGIOS_TYPE_CURRENT_HOST_STATE":    `CURRENT HOST STATE`,

	"NAGIOS_TYPE_SERVICE_NOTIFICATION": `SERVICE NOTIFICATION`,
	"NAGIOS_TYPE_HOST_NOTIFICATION":    `HOST NOTIFICATION`,

	"NAGIOS_TYPE_SERVICE_ALERT": `SERVICE ALERT`,
	"NAGIOS_TYPE_HOST_ALERT":    `HOST ALERT`,

	"NAGIOS_TYPE_SERVICE_FLAPPING_ALERT": `SERVICE FLAPPING ALERT`,
	"NAGIOS_TYPE_HOST_FLAPPING_ALERT":    `HOST FLAPPING ALERT`,

	"NAGIOS_TYPE_SERVICE_DOWNTIME_ALERT": `SERVICE DOWNTIME ALERT`,
	"NAGIOS_TYPE_HOST_DOWNTIME_ALERT":    `HOST DOWNTIME ALERT`,

	"NAGIOS_TYPE_PASSIVE_SERVICE_CHECK": `PASSIVE SERVICE CHECK`,
	"NAGIOS_TYPE_PASSIVE_HOST_CHECK":    `PASSIVE HOST CHECK`,

	"NAGIOS_TYPE_SERVICE_EVENT_HANDLER": `SERVICE EVENT HANDLER`,
	"NAGIOS_TYPE_HOST_EVENT_HANDLER":    `HOST EVENT HANDLER`,

	"NAGIOS_TYPE_EXTERNAL_COMMAND":      `EXTERNAL COMMAND`,
	"NAGIOS_TYPE_TIMEPERIOD_TRANSITION": `TIMEPERIOD TRANSITION`,
	//
	// End nagios log types
	//

	//
	// Begin external check types
	//
	"NAGIOS_EC_DISABLE_SVC_CHECK":              `DISABLE_SVC_CHECK`,
	"NAGIOS_EC_ENABLE_SVC_CHECK":               `ENABLE_SVC_CHECK`,
	"NAGIOS_EC_DISABLE_HOST_CHECK":             `DISABLE_HOST_CHECK`,
	"NAGIOS_EC_ENABLE_HOST_CHECK":              `ENABLE_HOST_CHECK`,
	"NAGIOS_EC_PROCESS_SERVICE_CHECK_RESULT":   `PROCESS_SERVICE_CHECK_RESULT`,
	"NAGIOS_EC_PROCESS_HOST_CHECK_RESULT":      `PROCESS_HOST_CHECK_RESULT`,
	"NAGIOS_EC_SCHEDULE_SERVICE_DOWNTIME":      `SCHEDULE_SERVICE_DOWNTIME`,
	"NAGIOS_EC_SCHEDULE_HOST_DOWNTIME":         `SCHEDULE_HOST_DOWNTIME`,
	"NAGIOS_EC_DISABLE_HOST_SVC_NOTIFICATIONS": `DISABLE_HOST_SVC_NOTIFICATIONS`,
	"NAGIOS_EC_ENABLE_HOST_SVC_NOTIFICATIONS":  `ENABLE_HOST_SVC_NOTIFICATIONS`,
	"NAGIOS_EC_DISABLE_HOST_NOTIFICATIONS":     `DISABLE_HOST_NOTIFICATIONS`,
	"NAGIOS_EC_ENABLE_HOST_NOTIFICATIONS":      `ENABLE_HOST_NOTIFICATIONS`,
	"NAGIOS_EC_DISABLE_SVC_NOTIFICATIONS":      `DISABLE_SVC_NOTIFICATIONS`,
	"NAGIOS_EC_ENABLE_SVC_NOTIFICATIONS":       `ENABLE_SVC_NOTIFICATIONS`,
	//
	// End external check types
	//
	"NAGIOS_WARNING": `Warning:%{SPACE}%{GREEDYDATA:nagios_message}`,

	"NAGIOS_CURRENT_SERVICE_STATE": `%{NAGIOS_TYPE_CURRENT_SERVICE_STATE:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{DATA:nagios_statetype};%{DATA:nagios_statecode};%{GREEDYDATA:nagios_message}`,
	"NAGIOS_CURRENT_HOST_STATE":    `%{NAGIOS_TYPE_CURRENT_HOST_STATE:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{DATA:nagios_statetype};%{DATA:nagios_statecode};%{GREEDYDATA:nagios_message}`,

	"NAGIOS_SERVICE_NOTIFICATION": `%{NAGIOS_TYPE_SERVICE_NOTIFICATION:nagios_type}: %{DATA:nagios_notifyname};%{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{DATA:nagios_contact};%{GREEDYDATA:nagios_message}`,
	"NAGIOS_HOST_NOTIFICATION":    `%{NAGIOS_TYPE_HOST_NOTIFICATION:nagios_type}: %{DATA:nagios_notifyname};%{DATA:nagios_hostname};%{DATA:nagios_state};%{DATA:nagios_contact};%{GREEDYDATA:nagios_message}`,

	"NAGIOS_SERVICE_ALERT": `%{NAGIOS_TYPE_SERVICE_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{DATA:nagios_statelevel};%{NUMBER:nagios_attempt};%{GREEDYDATA:nagios_message}`,
	"NAGIOS_HOST_ALERT":    `%{NAGIOS_TYPE_HOST_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{DATA:nagios_statelevel};%{NUMBER:nagios_attempt};%{GREEDYDATA:nagios_message}`,

	"NAGIOS_SERVICE_FLAPPING_ALERT": `%{NAGIOS_TYPE_SERVICE_FLAPPING_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{GREEDYDATA:nagios_message}`,
	"NAGIOS_HOST_FLAPPING_ALERT":    `%{NAGIOS_TYPE_HOST_FLAPPING_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{GREEDYDATA:nagios_message}`,

	"NAGIOS_SERVICE_DOWNTIME_ALERT": `%{NAGIOS_TYPE_SERVICE_DOWNTIME_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{GREEDYDATA:nagios_comment}`,
	"NAGIOS_HOST_DOWNTIME_ALERT":    `%{NAGIOS_TYPE_HOST_DOWNTIME_ALERT:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{GREEDYDATA:nagios_comment}`,

	"NAGIOS_PASSIVE_SERVICE_CHECK": `%{NAGIOS_TYPE_PASSIVE_SERVICE_CHECK:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{GREEDYDATA:nagios_comment}`,
	"NAGIOS_PASSIVE_HOST_CHECK":    `%{NAGIOS_TYPE_PASSIVE_HOST_CHECK:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{GREEDYDATA:nagios_comment}`,

	"NAGIOS_SERVICE_EVENT_HANDLER": `%{NAGIOS_TYPE_SERVICE_EVENT_HANDLER:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{DATA:nagios_statelevel};%{DATA:nagios_event_handler_name}`,
	"NAGIOS_HOST_EVENT_HANDLER":    `%{NAGIOS_TYPE_HOST_EVENT_HANDLER:nagios_type}: %{DATA:nagios_hostname};%{DATA:nagios_state};%{DATA:nagios_statelevel};%{DATA:nagios_event_handler_name}`,

	"NAGIOS_TIMEPERIOD_TRANSITION": `%{NAGIOS_TYPE_TIMEPERIOD_TRANSITION:nagios_type}: %{DATA:nagios_service};%{DATA:nagios_unknown1};%{DATA:nagios_unknown2}`,

	//
	// External checks
	//

	//Disable host & service check
	"NAGIOS_EC_LINE_DISABLE_SVC_CHECK":  `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_SVC_CHECK:nagios_command};%{DATA:nagios_hostname};%{DATA:nagios_service}`,
	"NAGIOS_EC_LINE_DISABLE_HOST_CHECK": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_HOST_CHECK:nagios_command};%{DATA:nagios_hostname}`,

	//Enable host & service check
	"NAGIOS_EC_LINE_ENABLE_SVC_CHECK":  `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_SVC_CHECK:nagios_command};%{DATA:nagios_hostname};%{DATA:nagios_service}`,
	"NAGIOS_EC_LINE_ENABLE_HOST_CHECK": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_HOST_CHECK:nagios_command};%{DATA:nagios_hostname}`,

	//Process host & service check
	"NAGIOS_EC_LINE_PROCESS_SERVICE_CHECK_RESULT": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_PROCESS_SERVICE_CHECK_RESULT:nagios_command};%{DATA:nagios_hostname};%{DATA:nagios_service};%{DATA:nagios_state};%{GREEDYDATA:nagios_check_result}`,
	"NAGIOS_EC_LINE_PROCESS_HOST_CHECK_RESULT":    `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_PROCESS_HOST_CHECK_RESULT:nagios_command};%{DATA:nagios_hostname};%{DATA:nagios_state};%{GREEDYDATA:nagios_check_result}`,

	//Disable host & service notifications
	"NAGIOS_EC_LINE_DISABLE_HOST_SVC_NOTIFICATIONS": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_HOST_SVC_NOTIFICATIONS:nagios_command};%{GREEDYDATA:nagios_hostname}`,
	"NAGIOS_EC_LINE_DISABLE_HOST_NOTIFICATIONS":     `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_HOST_NOTIFICATIONS:nagios_command};%{GREEDYDATA:nagios_hostname}`,
	"NAGIOS_EC_LINE_DISABLE_SVC_NOTIFICATIONS":      `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_DISABLE_SVC_NOTIFICATIONS:nagios_command};%{DATA:nagios_hostname};%{GREEDYDATA:nagios_service}`,

	//Enable host & service notifications
	"NAGIOS_EC_LINE_ENABLE_HOST_SVC_NOTIFICATIONS": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_HOST_SVC_NOTIFICATIONS:nagios_command};%{GREEDYDATA:nagios_hostname}`,
	"NAGIOS_EC_LINE_ENABLE_HOST_NOTIFICATIONS":     `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_HOST_NOTIFICATIONS:nagios_command};%{GREEDYDATA:nagios_hostname}`,
	"NAGIOS_EC_LINE_ENABLE_SVC_NOTIFICATIONS":      `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_ENABLE_SVC_NOTIFICATIONS:nagios_command};%{DATA:nagios_hostname};%{GREEDYDATA:nagios_service}`,

	//Schedule host & service downtime
	"NAGIOS_EC_LINE_SCHEDULE_HOST_DOWNTIME": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios_type}: %{NAGIOS_EC_SCHEDULE_HOST_DOWNTIME:nagios_command};%{DATA:nagios_hostname};%{NUMBER:nagios_start_time};%{NUMBER:nagios_end_time};%{NUMBER:nagios_fixed};%{NUMBER:nagios_trigger_id};%{NUMBER:nagios_duration};%{DATA:author};%{DATA:comment}`,

	//End matching line
	"NAGIOSLOGLINE": `%{NAGIOSTIME} (?:%{NAGIOS_WARNING}|%{NAGIOS_CURRENT_SERVICE_STATE}|%{NAGIOS_CURRENT_HOST_STATE}|%{NAGIOS_SERVICE_NOTIFICATION}|%{NAGIOS_HOST_NOTIFICATION}|%{NAGIOS_SERVICE_ALERT}|%{NAGIOS_HOST_ALERT}|%{NAGIOS_SERVICE_FLAPPING_ALERT}|%{NAGIOS_HOST_FLAPPING_ALERT}|%{NAGIOS_SERVICE_DOWNTIME_ALERT}|%{NAGIOS_HOST_DOWNTIME_ALERT}|%{NAGIOS_PASSIVE_SERVICE_CHECK}|%{NAGIOS_PASSIVE_HOST_CHECK}|%{NAGIOS_SERVICE_EVENT_HANDLER}|%{NAGIOS_HOST_EVENT_HANDLER}|%{NAGIOS_TIMEPERIOD_TRANSITION}|%{NAGIOS_EC_LINE_DISABLE_SVC_CHECK}|%{NAGIOS_EC_LINE_ENABLE_SVC_CHECK}|%{NAGIOS_EC_LINE_DISABLE_HOST_CHECK}|%{NAGIOS_EC_LINE_ENABLE_HOST_CHECK}|%{NAGIOS_EC_LINE_PROCESS_HOST_CHECK_RESULT}|%{NAGIOS_EC_LINE_PROCESS_SERVICE_CHECK_RESULT}|%{NAGIOS_EC_LINE_SCHEDULE_HOST_DOWNTIME}|%{NAGIOS_EC_LINE_DISABLE_HOST_SVC_NOTIFICATIONS}|%{NAGIOS_EC_LINE_ENABLE_HOST_SVC_NOTIFICATIONS}|%{NAGIOS_EC_LINE_DISABLE_HOST_NOTIFICATIONS}|%{NAGIOS_EC_LINE_ENABLE_HOST_NOTIFICATIONS}|%{NAGIOS_EC_LINE_DISABLE_SVC_NOTIFICATIONS}|%{NAGIOS_EC_LINE_ENABLE_SVC_NOTIFICATIONS})`,
}
