# LTI Tool Demo

A simple LTI 1.3 Tool Provider implementation using Go, HTMX, and Templ.

## Overview

This project demonstrates a basic implementation of an LTI 1.3 tool that can be integrated with any LMS (Learning Management System) that supports the LTI 1.3 standard, such as Canvas, Moodle, or Blackboard.

## Features

- Implements LTI 1.3 authentication flow
- Provides configuration endpoint for LMS integration
- Shows a personalized welcome screen for students and teachers
- Uses HTMX for dynamic content loading
- Uses Templ for templating

## Requirements

- Go 1.18 or higher
- Templ CLI tool

## Installation

1. Clone the repository
   ```
   git clone https://github.com/your-username/lti-tool-demo.git
   cd lti-tool-demo
   ```

2. Install dependencies
   ```
   go mod download
   ```

3. Install the templ CLI tool
   ```
   go install github.com/a-h/templ/cmd/templ@latest
   ```

4. Generate Go code from templ files
   ```
   templ generate
   ```

5. Run the application
   ```
   go run main.go
   ```

The application will start on port 8080 by default. You can change this by setting the PORT environment variable.

## Integration with an LMS

To integrate this tool with an LMS, you need to:

1. Start the LTI tool (locally or deployed)
2. Note the configuration URL printed in the console (e.g., `https://your-domain.com/lti/config`)
3. In your LMS, add a new LTI 1.3 tool using this configuration URL
4. Follow your LMS-specific instructions to complete the integration

For local development, you may need to use a tool like ngrok to expose your local server to the internet.

## Environment Variables

You can configure the tool using the following environment variables:

- `PORT`: The port to run the server on (default: 8080)
- `LTI_ISSUER`: The issuer URL (should match your domain)
- `LTI_CLIENT_ID`: The client ID to use for LTI authentication

## Development

To regenerate the templ files after making changes:

```
templ generate
```

## License

MIT 