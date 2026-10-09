# Custom detection rules

OT PCAP Analyzer can evaluate your own detection rules on every decoded OT event
(Modbus, S7comm, DNP3, IEC 104, GOOSE, ...). Rules are written in YAML or JSON and
work on the *decoded* event (protocol, operation, function code, target, value,
addresses), not on raw bytes.

## Using rules

* Pass rule files or directories on the command line: `--rules my_rules.yml --rules /etc/ot-rules/`
* Or drop them in `~/.ot_pcap_analyzer/rules/`. Every `*.yml`, `*.yaml` and `*.json` file
  there is loaded automatically.
* From Python:

  ```python
  from ot_pcap_analyzer.detection.rules_engine import RuleEngine
  engine = RuleEngine.from_paths(["examples/rules/example_rules.yml"])
  for event in sorted(events, key=lambda e: e.timestamp):
      anomalies.extend(engine.evaluate(event))
  ```

YAML needs PyYAML (`pip install pyyaml`). Without it, YAML files are skipped with a
warning and JSON files still work. Invalid rules are skipped with a warning that names
the file and the rule id. The other rules keep working.

Alerts show up as anomalies of type `CUSTOM_<RULE_ID>` (for example `CUSTOM_OTR_001`).

## File format

The top level is either a list of rules or a mapping `{rules: [...]}`.
See [`example_rules.yml`](example_rules.yml) for commented examples.

### Rule keys

| Key | Required | Description |
|-----|----------|-------------|
| `id` | yes | Unique id, characters `A-Z a-z 0-9 _ . -` |
| `name` | yes | Short title shown in the alert |
| `severity` | no | `LOW`, `MEDIUM` (default), `HIGH`, `CRITICAL` |
| `description` | no | Appended to the alert description |
| `recommendation` | no | What the operator should do |
| `mitre` | no | List of ATT&CK for ICS ids. Defaults to the event's techniques |
| `enabled` | no | `false` keeps the rule loaded but inactive |
| `match` | no | Conditions (see below). Omitting it matches every event |
| `threshold` | no | `{count, seconds, group_by}`: alert when `count` matches occur within `seconds` |
| `cooldown_seconds` | no | Suppress repeated alerts for the same group (default 60) |

### `match` conditions

All conditions must hold (AND). A list value means "any of" (OR).

| Key | Values | Matches |
|-----|--------|---------|
| `protocol` | `MODBUS_TCP`, `S7COMM`, `DNP3`, `IEC_104`, `IEC_61850_GOOSE`, ... (case-insensitive) | event protocol |
| `op` | `WRITE`, `SETPOINT`, `PLC_STOP`, `CONTROL_EXECUTE`, ... A trailing `*` matches a prefix (`"CONTROL_*"`) | canonical operation (`details.op`, or `WRITE`/`CONTROL`/`READ` from the operation type) |
| `function_code` | integers or hex strings (`"0x10"`) | protocol function code |
| `operation_type` | `READ`, `WRITE`, `CONTROL`, ... | event operation type |
| `risk_level` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | decoder risk level |
| `src_ip`, `dst_ip` | IPv4/IPv6 addresses, CIDRs, MAC addresses, `any`. `!` excludes | addresses. Positive entries are OR-ed and `!` entries are AND-ed |
| `src_port`, `dst_port` | ports or ranges (`"20000-20010"`), `!` excludes | ports |
| `unit_id` | integers | Modbus unit / station id |
| `target` | Python regular expression (`re.search`) | `details.target`, for example `"CA=1 IOA=4001"` or `"DB1"` |
| `value_gt`, `value_ge`, `value_lt`, `value_le`, `value_eq` | number | numeric `details.value` |
| `details` | mapping `{key: value}` | exact equality of `details` keys, for example `{goose_test: true}` |
| `is_request` | `true` / `false` | request vs response. Inferred from ports when the decoder does not say |

### Threshold and cooldown

`threshold.group_by` accepts `src_ip`, `dst_ip`, `protocol`, `function_code`, `target` and
`unit_id`. Counting is done separately per group, and with no `group_by` there is one global
counter. After an alert, the counter restarts. `cooldown_seconds` then suppresses further alerts
for the same group. Rules without a threshold apply the cooldown per `(src_ip, dst_ip)`
pair.

Unknown keys or bad values produce an error that names the rule id and the offending key,
for example: `rule OTR-001: unknown match key 'srcip' (did you mean 'src_ip'?)`.
