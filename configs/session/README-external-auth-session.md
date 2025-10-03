# External Authentication Session Script

This script provides session management for HawkScan when using external command-based authentication. It extracts authentication data (headers and cookies) from external command JSON output and validates the session against a specified endpoint.

## Features

- **JSON Processing**: Parses external command output in HawkScan's expected format
- **Cookie Management**: Automatically handles cookies via HttpState
- **Header Injection**: Injects authentication headers into scan requests
- **JWT Support**: Automatic JWT token parsing, expiration tracking, and renewal
- **Session Validation**: Tests extracted credentials against a validation endpoint
- **Error Handling**: Comprehensive logging and validation with meaningful error messages

## Required JSON Format

Your external authentication command must output JSON in this format, which is the documented standard format for HawkScan's `externalCommand` auth methodology:

```json
{
  "headers": [
    {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
    {"X-API-Key": "your-api-key-here"}
  ],
  "cookies": [
    {"JSESSIONID": "ABC123XYZ789"},
    {"XLOGINID": "user123"}
  ]
}
```

## Configuration

As per any other HawkScan script, the `external-auth-session.kts` must be placed in a directory hierarchy as follows:

```aiignore
CWD (where stackhawk.yml lives)
  |__hawkscripts (or scripts, but make sure the config file path setting matches)
    |__session
      |__external-auth-session.kts
```

### stackhawk.yml Example

```yaml
app:
  applicationId: your-app-id-here
  env: Development
  host: https://localhost:9000

# External command authentication
authentication:
  externalCommand:
    command: "sh"
    parameters:
      - "-c"
      - "./scripts/get-auth-token.sh"
  sessionScript:
    name: external-auth-session.kts
    parameters:
      validation_url: "https://localhost:9000/api/user/profile" ##example
      validation_regex: '.*200.*' ##example, but very common, recommended

# Session management with validation
hawkAddOn:
  scripts:
    - name: "external-auth-session.kts"
      type: "session"
      path: "hawkscripts"
      language: "KOTLIN"
```

### Script Parameters

#### Required Parameters
- **`validation_url`**: URL to test the extracted session credentials against
- **`validation_regex`**: Regex pattern to match against the validation response (headers + body)

#### Example Validation Patterns
- `.*200.*` - Matches HTTP 200 responses
- `.*"authenticated":\s*true.*` - Matches JSON response with authenticated: true
- `.*Welcome.*` - Matches responses containing "Welcome"
- `HTTP/1.1 2\d\d` - Matches any 2xx HTTP status code

## External Authentication Script Example

Your external command should output the required JSON format. Here's a simple bash example:

```bash
#!/bin/bash
# get-auth-token.sh

# Perform authentication (example using curl)
TOKEN=$(curl -s -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"your-client","client_secret":"your-secret"}' \
  | jq -r '.access_token')

# Output in HawkScan format
cat <<EOF
{
  "headers": [
    {"Authorization": "Bearer $TOKEN"}
  ],
  "cookies": []
}
EOF
```

## How It Works

1. **Authentication**: HawkScan executes your external command
2. **Extraction**: Script parses JSON output and stores headers/cookies
3. **Validation**: Script tests credentials against your validation endpoint
4. **Session Management**: Headers are injected into all scan requests
5. **JWT Handling**: If JWT tokens are present, automatic expiration checking and renewal occurs
6. **Cookie Management**: Cookies are automatically managed by HttpState

## Validation Process

The script performs these validation steps:

1. Creates HTTP GET request to `validation_url`
2. Applies all extracted headers and cookies
3. Sends request and captures response
4. Tests response against `validation_regex` pattern
5. **Success**: Logs success message and continues scan
6. **Failure**: Logs detailed error message and exits with code 1

## Error Handling

The script provides comprehensive error handling for:

- Missing required parameters
- Invalid JSON format from external command
- Network failures during validation
- JWT parsing errors
- Session management failures

All errors are logged with detailed messages and cause of scan failure for rapid debugging when using HawkScan's `debug` mode.

## Future State Possibilities

The script currently uses a hard-coded refresh time of 5 minutes prior to the expiration of a provided JWT.  Future state could make that value configurable if it was needed. Obviously, this script can also be used as a starting point and completely customized to include alternate session management logic.

Other thoughts? Provide feedback to your friendly neighborhood StackHawk solutions architect.