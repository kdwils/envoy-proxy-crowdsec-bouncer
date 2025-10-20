# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Envoy Proxy CrowdSec Bouncer is a security proxy service written in Go that integrates Envoy Gateway's external authorization with CrowdSec's threat intelligence and remediation capabilities. It provides WAF inspection, IP-based bouncing, and CAPTCHA challenges for suspicious traffic.

## Development Commands

### Building & Running
```bash
go build -o envoy-proxy-bouncer main.go  # Build the binary
./envoy-proxy-bouncer serve               # Start the bouncer server
```

### Code Generation
```bash
go generate ./...           # Generate mocks and other generated code
```

### Testing
```bash
go test ./...               # Run all tests
go test -v ./remediation/   # Run specific package tests with verbose output
go test -race ./...         # Run tests with race detection
go test -cover ./...        # Run tests with coverage
go test -tags functional ./tests/... -v  # Run functional tests
```

### Linting & Type Checking
```bash
go fmt ./...                # Format code
go vet ./...                # Vet code for issues
```

### Development Workflow
1. Make requested changes
2. Run `go fmt ./...` to format the code
3. Run `go test ./...` to run tests
4. Fix any errors
5. Repeat

### Kubernetes Deployment
```bash
helm install envoy-proxy-bouncer ./charts/envoy-proxy-bouncer  # Install chart
helm upgrade envoy-proxy-bouncer ./charts/envoy-proxy-bouncer  # Upgrade chart
```

## Architecture Overview

### Core Components

**Main Entry Point**: `main.go` → `cmd/root.go` using Cobra for CLI commands

**gRPC/HTTP Server**: `server/server.go` provides dual-mode server
- gRPC server implementing Envoy's external authorization service
- HTTP server for CAPTCHA verification endpoints when enabled
- Configurable ports (gRPC default 8080, HTTP default 8081)

**Remediation Engine**: `remediation/remediator.go` orchestrates security checks
- Coordinates between Bouncer, WAF, and CAPTCHA components
- Sequential processing: Bouncer → WAF → CAPTCHA (only if WAF triggers it)
- Parses Envoy CheckRequest and extracts real client IP

**Security Components**:
- `remediation/components/bouncer.go` - CrowdSec integration for IP-based decisions
- `remediation/components/waf.go` - Web Application Firewall inspection
- `remediation/components/captcha.go` - CAPTCHA challenge management

### Configuration Management

Uses Viper with hierarchy: CLI flags → ENV vars (ENVOY_BOUNCER_*) → config file → defaults

Key config sections defined in `cmd/root.go:initConfig()`:
- Server ports (gRPC and HTTP)
- Bouncer settings (CrowdSec API key, LAPI URL, ticker interval)
- WAF settings (AppSec URL, API key)
- CAPTCHA settings (provider, site key, secret key, hostname)
- Trusted proxies for IP extraction

### Remediation Flow

1. **Bouncer Check**: Query CrowdSec for IP-based ban decisions
2. **WAF Inspection**: Send request to AppSec for analysis (if bouncer allows)
3. **CAPTCHA Challenge**: Present challenge if WAF returns "captcha" action
4. **Response Generation**: Convert decisions to appropriate Envoy responses

### External Integrations

**CrowdSec Integration**:
- Stream bouncer for real-time decision updates
- Metrics reporting for processed/bounced requests
- Live bouncer for on-demand IP checks

**WAF Integration**:
- AppSec API for request inspection
- Supports custom WAF backends

**CAPTCHA Providers**:
- reCAPTCHA v2 support
- Cloudflare Turnstile support
- Session management with secure tokens

### IP Extraction Logic

Handles real client IP extraction from headers and trusted proxies:
- Checks `X-Forwarded-For` header (case-insensitive)
- Falls back to `X-Real-IP` header
- Respects trusted proxy configuration
- Validates IP format before use

### Generated Code

The project uses code generation for mocks:
- `//go:generate mockgen` directives for interfaces
- Mock files in `mocks/` folders next to components
- Separate mocks for different interface types

Run `go generate ./...` to regenerate all mocks.

### Key Patterns

**Interface-based Design**: All components use interfaces (Bouncer, WAF, Captcha)
**Dependency Injection**: Components injected into Remediator constructor
**Context Propagation**: All operations use context.Context for cancellation and logging
**Structured Logging**: Uses slog with context-aware logging via `logger` package

### Testing Strategy

The project uses `gomock` library for mocking and `testify` for assertions.

**Component Testing**: Each security component has dedicated test files with mocks

**Mock Setup Example**:
```go
ctrl := gomock.NewController(t)
defer ctrl.Finish()

mb := remediationmocks.NewMockBouncer(ctrl)
mw := remediationmocks.NewMockWAF(ctrl)
mc := servermocks.NewMockCaptcha(ctrl)  // Note: server mocks for Captcha interface

r := Remediator{Bouncer: mb, WAF: mw, CaptchaService: mc}

mb.EXPECT().Bounce(gomock.Any(), "1.2.3.4", gomock.Any()).Return(false, nil)
mw.EXPECT().Inspect(gomock.Any(), gomock.AssignableToTypeOf(components.AppSecRequest{})).Return(components.WAFResponse{Action: "captcha"}, nil)
```

**Test Assertions - Use testify/assert and testify/require**:
- ALWAYS use `github.com/stretchr/testify/assert` and `github.com/stretchr/testify/require` for assertions
- Use `require` for critical assertions where test cannot continue if it fails (e.g., checking if value exists before using it)
- Use `assert` for non-critical assertions where test should continue to check other conditions
- NEVER use `require.Contains()` or `assert.Contains()` - it's lazy and inaccurate
- ALWAYS check each condition individually with clear, specific messages
- Test exact values, not partial matches

**Good Test Assertion Examples**:
```go
// Good - Individual assertions with clear messages
val1, ok1 := cache.Get("key1")
assert.True(t, ok1, "expected key1 to exist in cache")
assert.Equal(t, "value1", val1, "expected key1 to have correct value")

val2, ok2 := cache.Get("key2")
assert.True(t, ok2, "expected key2 to exist in cache")
assert.Equal(t, "value2", val2, "expected key2 to have correct value")

// Good - Use require when you need the value to continue
got, ok := c.Get(ip)
require.True(t, ok, "expected to find entry for %s", ip)
assert.Equal(t, ip, *got.Value, "expected correct IP value")
```

**Bad Test Assertion Examples**:
```go
// Bad - Combined conditions make it unclear which failed
if !ok1 || !ok2 {
    t.Error("expected entries to exist")
}

// Bad - No message indicating what's being tested
assert.True(t, ok)

// Bad - Using Contains for exact matches
assert.Contains(t, result, "expected_value")
```

**Mock Locations**:
- `bouncer/mocks/` - Bouncer and WAF mocks
- `server/mocks/` - Captcha interface mocks
- `bouncer/components/mocks/` - CaptchaProvider mocks

### Kubernetes Integration

**Helm Chart**: `charts/envoy-proxy-bouncer/`
- Deployment with configurable replicas
- Service exposure for gRPC and HTTP ports
- ConfigMap for application configuration
- Support for environment variable overrides

**Port Configuration**:
- gRPC port always exposed for Envoy integration
- HTTP port only exposed when CAPTCHA is enabled
- Defaults: gRPC 8080, HTTP 8081

### CLI Commands Available

**Core Operations**:
- `envoy-proxy-bouncer serve` - Start the bouncer server

## Code Style

- DO NOT ADD ***ANY*** COMMENTS unless asked
- DO NOT use else statements - prefer early returns, overwriting variables, or helper functions
- Set default values first, then conditionally override them instead of using if/else
- Avoid unnecessary comments explaining what the code does