# REST API

sqlmap can be controlled through an HTTP REST API by using `sqlmapapi.py`. The API accepts and returns JSON. This is useful when sqlmap has to be integrated into another tool, service, user interface, automation pipeline or commercial product.

The API server manages scan tasks. A client creates a task, sets sqlmap options, starts a scan, then retrieves status, logs, data and output files.

> **Note**
>
> Use sqlmap and its API only against targets you are authorized to test.

## Starting the API server

Start the REST API server with `-s` or `--server`:

```bash
python sqlmapapi.py -s --username sqlmap --password sqlmap
```

By default, the server listens on `127.0.0.1:8775`.

Common server options:

```bash
python sqlmapapi.py -s \
  -H 127.0.0.1 \
  -p 8775 \
  --username sqlmap \
  --password sqlmap
```

Available API-specific command line options:

| Option | Description |
| --- | --- |
| `-s`, `--server` | Run as a REST API server |
| `-c`, `--client` | Run as a REST API client |
| `-H`, `--host` | Host of the REST API server |
| `-p`, `--port` | Port of the REST API server |
| `--adapter` | Server adapter to use |
| `--database` | IPC database file path |
| `--username` | Basic authentication username |
| `--password` | Basic authentication password |

When using `sqlmapapi.py` in server or client mode, both `--username` and `--password` are required.

## Authentication

The API uses HTTP Basic authentication.

With `curl`, use `-u`:

```bash
curl -u sqlmap:sqlmap http://127.0.0.1:8775/version
```

For the examples below, it is convenient to define the API address and credentials first:

```bash
API="http://127.0.0.1:8775"
AUTH="sqlmap:sqlmap"
```

Then requests can be written as:

```bash
curl -u "$AUTH" "$API/version"
```

## Basic workflow

A typical API workflow is:

1. Start the API server.
2. Create a new task.
3. Start a scan by sending sqlmap options as JSON.
4. Poll the scan status.
5. Retrieve logs and data.
6. Stop, kill or delete the task if needed.

Example:

```bash
API="http://127.0.0.1:8775"
AUTH="sqlmap:sqlmap"

taskid=$(curl -s -u "$AUTH" "$API/task/new" | grep -o '[a-f0-9]\{16\}')

curl -u "$AUTH" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"url":"https://sekumart.sekuripy.hr/product.php?id=1"}' \
  "$API/scan/$taskid/start"

curl -u "$AUTH" "$API/scan/$taskid/status"
curl -u "$AUTH" "$API/scan/$taskid/log"
curl -u "$AUTH" "$API/scan/$taskid/data"
```

The JSON options used with `/scan/<taskid>/start` correspond to sqlmap's internal option names. For example, command line option `--url` is represented as JSON key `url`.

## Response format

Most API responses are JSON objects containing a `success` field.

Successful response example:

```json
{
  "success": true,
  "taskid": "1a2b3c4d5e6f7890"
}
```

Error response example:

```json
{
  "success": false,
  "message": "Invalid task ID"
}
```

Some API-level errors are returned with HTTP status `200` and `success: false`, matching the current implementation behavior. HTTP status codes such as `401`, `404`, `405` and `500` can also be returned for authentication errors, missing routes, invalid methods and server errors.

## Version

### `GET /version`

Returns the sqlmap version and the API contract version exposed by the server.

`api_version` is the MAJOR version of the REST API contract (semantic versioning), independent of the sqlmap version. Only the major is exposed at runtime because only a major bump breaks clients; use it to check compatibility (e.g. `api_version == 2`).

Example:

```bash
curl -u "$AUTH" "$API/version"
```

Response:

```json
{
  "success": true,
  "version": "1.10.7.176#dev",
  "api_version": 2
}
```

## Task management

A task represents one sqlmap scan context. Options are stored per task, and scans are started against a task ID.

### `GET /task/new`

Creates a new task.

Example:

```bash
curl -u "$AUTH" "$API/task/new"
```

Response:

```json
{
  "success": true,
  "taskid": "1a2b3c4d5e6f7890"
}
```

Save the task ID for later requests:

```bash
taskid=$(curl -s -u "$AUTH" "$API/task/new" | grep -o '[a-f0-9]\{16\}')
echo "$taskid"
```

### `GET /task/<taskid>/delete`

Deletes an existing task and kills its scan process if it is still running.

Example:

```bash
curl -u "$AUTH" "$API/task/$taskid/delete"
```

Response:

```json
{
  "success": true
}
```

## Options

Options can be set separately before starting a scan, or passed directly to `/scan/<taskid>/start`.

### `GET /option/<taskid>/list`

Lists current task options.

Example:

```bash
curl -u "$AUTH" "$API/option/$taskid/list"
```

Response excerpt:

```json
{
  "success": true,
  "options": {
    "url": null,
    "data": null,
    "cookie": null,
    "level": 1,
    "risk": 1,
    "batch": true
  }
}
```

### `POST /option/<taskid>/get`

Retrieves selected option values.

Example:

```bash
curl -u "$AUTH" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '["url", "level", "risk"]' \
  "$API/option/$taskid/get"
```

Response:

```json
{
  "success": true,
  "options": {
    "url": null,
    "level": 1,
    "risk": 1
  }
}
```

Unknown option example:

```json
{
  "success": false,
  "message": "Unknown option 'doesNotExist'"
}
```

### `POST /option/<taskid>/set`

Sets one or more task options.

Example:

```bash
curl -u "$AUTH" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"url":"https://sekumart.sekuripy.hr/product.php?id=1","level":2,"risk":1}' \
  "$API/option/$taskid/set"
```

Response:

```json
{
  "success": true
}
```

Unsupported, read-only and unknown options are rejected. An unknown (e.g. misspelled) option is rejected with an `Unknown option ...` message:

```json
{
  "success": false,
  "message": "Unknown option 'doesNotExist'"
}
```

A handful of interactive/CLI-only options cannot be driven over the API and are rejected as unsupported (`Unsupported option '<name>'`): `sqlShell`, `wizard`, `evalCode`, `alert` and `reportJson`.

Read-only API-controlled options include `api`, `taskid` and `database`.

## Scans

### `POST /scan/<taskid>/start`

Starts a scan for an existing task. The request body contains sqlmap options in JSON form.

Example:

```bash
curl -u "$AUTH" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"url":"https://sekumart.sekuripy.hr/product.php?id=1"}' \
  "$API/scan/$taskid/start"
```

Response:

```json
{
  "success": true,
  "engineid": 12345
}
```

You can also pass more sqlmap options:

```bash
curl -u "$AUTH" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"url":"https://sekumart.sekuripy.hr/product.php?id=1","batch":true,"level":2,"risk":1,"technique":"BEUSTQ"}' \
  "$API/scan/$taskid/start"
```

If a scan is already running for that task, the API returns:

```json
{
  "success": false,
  "message": "Scan already running"
}
```

### `GET /scan/<taskid>/status`

Returns scan status.

Example:

```bash
curl -u "$AUTH" "$API/scan/$taskid/status"
```

Response while running:

```json
{
  "success": true,
  "status": "running",
  "returncode": null
}
```

Possible status values are:

| Status | Description |
| --- | --- |
| `not running` | The task exists, but no scan process has been started |
| `running` | The scan process is still running |
| `terminated` | The scan process has finished |

### `GET /scan/<taskid>/stop`

Stops a running scan by terminating the scan process.

Example:

```bash
curl -u "$AUTH" "$API/scan/$taskid/stop"
```

Response:

```json
{
  "success": true
}
```

### `GET /scan/<taskid>/kill`

Kills a running scan process.

Example:

```bash
curl -u "$AUTH" "$API/scan/$taskid/kill"
```

Response:

```json
{
  "success": true
}
```

## Logs and data

### `GET /scan/<taskid>/log`

Retrieves all log messages for a task.

Example:

```bash
curl -u "$AUTH" "$API/scan/$taskid/log"
```

Response:

```json
{
  "success": true,
  "log": [
    {
      "time": "12:34:56",
      "level": "INFO",
      "message": "testing connection to the target URL"
    }
  ]
}
```

### `GET /scan/<taskid>/log/<start>/<end>`

Retrieves a subset of log messages by numeric row range.

Example:

```bash
curl -u "$AUTH" "$API/scan/$taskid/log/1/20"
```

Response:

```json
{
  "success": true,
  "log": [
    {
      "time": "12:34:56",
      "level": "INFO",
      "message": "testing connection to the target URL"
    }
  ]
}
```

Invalid range example:

```json
{
  "success": false,
  "message": "Invalid start or end value, must be digits"
}
```

### `GET /scan/<taskid>/data`

Retrieves structured scan data and errors.

Example:

```bash
curl -u "$AUTH" "$API/scan/$taskid/data"
```

Response:

```json
{
  "success": true,
  "data": [
    {
      "status": 1,
      "type": 2,
      "type_name": "DBMS_FINGERPRINT",
      "value": "back-end DBMS: MySQL >= 5.1"
    },
    {
      "status": 1,
      "type": 4,
      "type_name": "CURRENT_USER",
      "value": "root@%"
    }
  ],
  "error": []
}
```

Each item has a numeric `type`, its readable `type_name` (e.g. `TARGET`, `TECHNIQUES`, `DBMS_FINGERPRINT`, `BANNER`, `CURRENT_USER`, `DBS`, `TABLES`, `COLUMNS`, `DUMP_TABLE`), a `status` (`0` = in progress, `1` = complete) and a `value`. `type_name` is `null` for any unmapped type.

The shape of `value` depends on the type (string, number, boolean, array, object or `null`). Internal detection/plumbing fields are not exposed and SQL identifiers are unquoted. Notable shapes:

- `TECHNIQUES` — a list of injection points; each point's `data` is a list of techniques, each named via a `technique` field:

  ```json
  {
    "place": "GET", "parameter": "id", "dbms": "MySQL", "dbms_version": [">= 5.1"], "os": null, "notes": [],
    "data": [
      {"technique": "boolean-based blind", "title": "AND boolean-based blind - WHERE or HAVING clause", "payload": "id=1 AND 7997=7997", "vector": "AND [INFERENCE]", "comment": ""}
    ]
  }
  ```

- `DUMP_TABLE` — `{"db": ..., "table": ..., "count": N, "columns": {"<column>": [values, ...]}}`. A database `NULL` value is reported as JSON `null`.

## Downloading output files

### `GET /download/<taskid>/<target>/<filename>`

Downloads a file from sqlmap's output directory. The response contains Base64-encoded file content.

Example:

```bash
curl -u "$AUTH" "$API/download/$taskid/sekumart.sekuripy.hr/log"
```

Response:

```json
{
  "success": true,
  "file": "YmFzZTY0LWVuY29kZWQgZmlsZSBjb250ZW50"
}
```

The `filename` part can refer to a nested file path under the target output directory. Depending on the client, slashes in nested file names may need to be URL-encoded.

If the file does not exist:

```json
{
  "success": false,
  "message": "File does not exist"
}
```

## Admin operations

The server prints an admin token when started:

```text
Admin (secret) token: 0123456789abcdef0123456789abcdef
```

Admin endpoints can be called with or without the token. Without the admin token, list and flush operations are limited to tasks created from the same remote address. With the admin token, they apply to the whole task pool.

### `GET /admin/list`

Lists visible tasks.

Example:

```bash
curl -u "$AUTH" "$API/admin/list"
```

Response:

```json
{
  "success": true,
  "tasks": {
    "1a2b3c4d5e6f7890": "running"
  },
  "tasks_num": 1
}
```

### `GET /admin/<token>/list`

Lists all tasks when a valid admin token is supplied.

Example:

```bash
ADMIN_TOKEN="0123456789abcdef0123456789abcdef"
curl -u "$AUTH" "$API/admin/$ADMIN_TOKEN/list"
```

Response:

```json
{
  "success": true,
  "tasks": {
    "1a2b3c4d5e6f7890": "running"
  },
  "tasks_num": 1
}
```

### `GET /admin/flush`

Deletes visible tasks and kills their scan processes.

Example:

```bash
curl -u "$AUTH" "$API/admin/flush"
```

Response:

```json
{
  "success": true
}
```

### `GET /admin/<token>/flush`

Deletes all tasks when a valid admin token is supplied.

Example:

```bash
curl -u "$AUTH" "$API/admin/$ADMIN_TOKEN/flush"
```

Response:

```json
{
  "success": true
}
```

## Interactive API client

sqlmap also includes an interactive API client:

```bash
python sqlmapapi.py -c --username sqlmap --password sqlmap
```

To connect to a non-default server address:

```bash
python sqlmapapi.py -c \
  -H 127.0.0.1 \
  -p 8775 \
  --username sqlmap \
  --password sqlmap
```

Useful client commands include:

| Command | Description |
| --- | --- |
| `new ARGS` | Start a new scan task with sqlmap command line arguments |
| `use TASKID` | Switch current client context to an existing task |
| `data` | Retrieve data for the current task |
| `log` | Retrieve logs for the current task |
| `status` | Retrieve status for the current task |
| `option OPTION` | Retrieve an option value for the current task |
| `options` | Retrieve all options for the current task |
| `stop` | Stop the current task |
| `kill` | Kill the current task |
| `list` | Display visible tasks |
| `flush` | Flush visible tasks |
| `version` | Fetch server and API version |
| `exit` | Exit the client |

Example:

```text
api> new -u "https://sekumart.sekuripy.hr/product.php?id=1"
api (1a2b3c4d5e6f7890)> status
api (1a2b3c4d5e6f7890)> log
api (1a2b3c4d5e6f7890)> data
```

## OpenAPI specification

The REST API can also be described with the OpenAPI specification file:

```text
sqlmapapi.yaml
```

That file can be used by API documentation tools, client generators and API testing tools.

Validate the specification with Redocly:

```bash
npm install -g @redocly/cli
redocly lint sqlmapapi.yaml
```

## Using with Postman

Postman can import an OpenAPI specification directly. Import `sqlmapapi.yaml`, set Basic authentication credentials, and use the generated requests.

A standalone Postman collection can also be generated from the OpenAPI file:

```bash
npm install -g openapi-to-postmanv2

openapi2postmanv2 \
  -s sqlmapapi.yaml \
  -o sqlmapapi.postman_collection.json \
  -p \
  -O folderStrategy=Tags,includeAuthInfoInExample=true
```

The OpenAPI file should be treated as the canonical machine-readable API description. A generated Postman collection is only a convenience artifact.

## Integration notes

The REST API is intended to be used by trusted clients and trusted integrations.

Important notes for integrators:

* Do not expose the API server directly to untrusted networks.
* Use strong Basic authentication credentials.
* Bind the API server to `127.0.0.1` unless remote access is required.
* Place the API behind a properly configured reverse proxy if TLS, access control or network policy enforcement is needed.
* Treat task IDs as sensitive identifiers. Any authenticated client that knows a task ID can operate on that task.
* The API is not designed as a multi-tenant service boundary.
* Some mutating operations use `GET` requests for historical compatibility. Avoid placing the API behind caching layers that could replay or cache those requests.
* Scan options are validated by the API before being accepted. Unsupported, read-only and unknown options are rejected.
* The scan engine runs in a separate process. Long-running scans should be monitored through `/scan/<taskid>/status`, `/scan/<taskid>/log` and `/scan/<taskid>/data`.

## Minimal end-to-end example

```bash
API="http://127.0.0.1:8775"
AUTH="sqlmap:sqlmap"

# Create a task
taskid=$(curl -s -u "$AUTH" "$API/task/new" | grep -o '[a-f0-9]\{16\}')
echo "Task ID: $taskid"

# Start a scan
curl -u "$AUTH" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"url":"https://sekumart.sekuripy.hr/product.php?id=1","batch":true}' \
  "$API/scan/$taskid/start"

# Poll status
curl -u "$AUTH" "$API/scan/$taskid/status"

# Retrieve logs
curl -u "$AUTH" "$API/scan/$taskid/log"

# Retrieve data
curl -u "$AUTH" "$API/scan/$taskid/data"

# Delete task
curl -u "$AUTH" "$API/task/$taskid/delete"
```
