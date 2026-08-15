# AGENTS.md

Guidance for agents working in this repository. Module: `github.com/kdwils/envoy-proxy-bouncer` (Go 1.26).

## Project Overview

Envoy Proxy CrowdSec Bouncer is a security proxy service written in Go that integrates Envoy Proxy's external authorization with CrowdSec's threat intelligence and remediation capabilities. It provides IP-based banning (streamed decisions), WAF inspection via CrowdSec AppSec, and CAPTCHA challenges (Google reCAPTCHA v2, Cloudflare Turnstile) for suspicious traffic.

### Package Layout

- `bouncer/` — `Bouncer` type with the core `Check` request hot path: `ParseCheckRequest`, `ExtractRealIP`, decision-cache / CAPTCHA / WAF orchestration, and the `WAF`, `DecisionCache`, `CaptchaService` interfaces.
- `bouncer/components/` — concrete components: decision cache, AppSec WAF client, CAPTCHA service with reCAPTCHA and Turnstile providers, Prometheus recorder integration, HTTP client interface.
- `server/` — dual-mode server: gRPC ext_authz (`envoy.service.auth.v3.Authorization/Check`, reflection-enabled) on `:8080` plus HTTP CAPTCHA verify endpoints on `:8081`, per-IP rate limiting, and the `Bouncer` / `TemplateStore` / `Notifier` service interfaces.
- `pkg/cache/` — generic in-memory cache with TTL cleanup used by the decision cache and CAPTCHA sessions.
- `pkg/crowdsec/` — CrowdSec LAPI client (TLS, cert auth) and metrics reporting service.
- `config/` — Viper-based config structs and validation.
- `template/` — HTML template store (`RenderDenied`, `RenderCaptcha`) for ban/captcha pages.
- `webhook/` — webhook notifier service for remediation events.
- `recorder/` — Prometheus metrics recorder.
- `logger/` — context-aware `slog` helpers.
- `cmd/` — cobra CLI wiring (`serve`, `bounce`, `version`).
- `version/` — embedded version string.
- `tests/functional/` — testcontainers-based functional tests (build tag `functional`).

## Commands

```bash
go build -o envoy-proxy-bouncer .                          # Build the binary
go test -race ./...                                        # Unit tests with race detector
go test -tags functional ./tests/functional -v             # Functional tests (needs Docker)
go test -bench=. -benchmem -run=^$ ./...                   # Benchmarks
go generate ./...                                          # Regenerate mocks (go.uber.org/mock)
go vet ./...                                               # Lint / static analysis
gofmt -l .                                                 # Check formatting
```

## Code Style

- No comments unless asked.
- Never `else` — use early returns, or set a default value and override it conditionally.

## Testing Rules

- Use `t.Context()` for test contexts — never `context.Background()`. It is canceled when the test finishes, so it cannot leak goroutines past the test.

### Test structure

- **Tests go in the file they test** — `recaptcha.go` is tested by `recaptcha_test.go`, never by a shared/merged test file covering multiple sources.
- **Never write mocks in test files** — mocks are generated from interfaces (`go generate ./...`, go.uber.org/mock). Every mock used in a test comes from the generated packages (`bouncer/mocks`, `bouncer/components/mocks`, etc.); never hand-roll a mock, fake, stub, or `gomock.Matcher`. Capture and assert captured request arguments inline with `gomock.Any()` + `.Do(...)`.
- **Never use inline constructors in tests** — always call the real constructor (`New...`/`New(...)`) when one exists; never hand-assemble the struct with a literal to skip the constructor's wiring (field defaults, config parsing, component setup). Where a component must be substituted, construct via the real constructor first, then assign the mock to the component field directly in the test body.
- **No custom test structs** — no helper structs, `spec` tables, or wrapper types that bundle collaborators together.
- **Assertions are made in each test case** — write the `assert.Equal(t, want, got)` at the call site; never extract assertions into helper functions.
- Fixture helpers are limited to wrapping a real constructor with fixed inputs (e.g. `newMetricsService(t)`) and building request payloads / expected values (`mkCheckRequest`, `wantParsed`).

### Assertions

- testify only (`github.com/stretchr/testify`): `require` when the test cannot continue past the assertion, `assert` otherwise.
- **Compare the entire `got` vs `want`** — `assert.Equal(t, want, got)` on the whole expected object, not field-by-field. This means entire slices, every struct field, full nested structures — not a subset.
- **Explicit zero values** — if an expected item is a zero value, write it out explicitly in the expected literal; never rely on Go's implicit zero value (e.g. include `Headers: nil`, `Body: nil`, `UserAgent: ""`, `wantSuccess: false`).
- For fields that are deterministic, always compare everything: all fields, all elements, the whole value.
- Field-level assertions only for types with unexported or nondeterministic fields; then `assert.NotEmpty` the random field and compare the rest.
- No field-picking by habit.

### No redundancy

- **Table-driven tests for deterministic cases** — use a table when the cases need no mocks or external setup (no mock clients, temp files, testcontainers, real services, etc.).
- **Individual `t.Run` subtests for cases with external setup** — when a case requires mocks, temp files, or other external scaffolding, give it its own `t.Run` block; do not force such cases into a table.
- One distinct code path per case — no input permutations exercising identical paths; no duplicate subtests. A case that differs only in the data passed (e.g. value `42` vs `0`, or calling the method 1× vs 3×) is the same code path and is redundant — drop it unless it hits a genuinely different branch. For example, a `Set(key, value)` with no `exists` branch does not warrant separate "new" / "overwrite" / "zero value" cases: they all execute the same statements.
- Shared fixture helpers for repeated setup (bouncer construction, request builders, config literals).
- Assert behavior at one layer only.

### Performance in unit tests

- Hot paths (`Bouncer.Check`, `ParseCheckRequest`, `ExtractRealIP`, cache, template render) must have benchmarks (with `-benchmem`).
- PRs must not regress them (benchstat gate).

### Functional tests

- Shared fixture helpers; poll-don't-sleep (no blind `time.Sleep`).
- Latest CrowdSec image only on PRs; full image matrix on nightly/main.
- Reuse environments to avoid CrowdSec hub / Docker Hub rate limiting.

### Load testing

- k6 gRPC against `:8080` (reflection-enabled) with SLO thresholds, wired into CI on PRs.
