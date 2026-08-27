# AGENTS.md

Envoy ext_authz service (Go 1.26, module `github.com/kdwils/envoy-proxy-bouncer`) that bounces malicious traffic using CrowdSec: streamed IP decisions (ban/captcha), AppSec WAF inspection, and CAPTCHA challenges (reCAPTCHA v2, Cloudflare Turnstile).

## Project map

- `bouncer/` — `Bouncer` type with the core `Check` hot path: `ParseCheckRequest`, `ExtractRealIP`, decision-cache / CAPTCHA / WAF orchestration; defines `WAF`, `DecisionCache`, `CaptchaService` interfaces.
- `captcha/` — CAPTCHA service with reCAPTCHA v2 and Cloudflare Turnstile providers; defines `CaptchaProvider` interface.
- `decisions/` — streaming IP decision cache backed by the CrowdSec LAPI stream.
- `waf/` — AppSec WAF client for request inspection.
- `types/` — shared types; defines `HTTPClient` interface.
- `server/` — `ServeDual` runs three listeners: gRPC ext_authz on `:8080`, HTTP CAPTCHA verify with per-IP rate limiting on `:8081`, Prometheus `/metrics` on `:9090`. Service interfaces (`Bouncer`, `TemplateStore`, `Notifier`) live in `server/services.go`; shared test helpers in `server/testing/`.
- `pkg/cache/` — generic in-memory cache with TTL cleanup used by the decision cache and CAPTCHA sessions.
- `pkg/crowdsec/` — CrowdSec LAPI client (TLS, cert auth) and metrics reporting service.
- `config/` — config structs, validation, and defaults (all wired via `GetViper` in `config.go`).
- `template/` — HTML template store (`RenderDenied`, `RenderCaptcha`) for ban/captcha pages.
- `webhook/`, `recorder/`, `logger/` — webhook notifier, Prometheus recorder, `slog` helpers.
- `cmd/` — cobra CLI (`serve`, `bounce`, `version`).
- `version/` — `Version` is `go:embed`ded from `version/version.txt`; bump that file to change the version.
- `tests/functional/` — testcontainers-based functional tests behind the `functional` build tag.

<important if="you need to run commands to build, test, lint, or generate code">

```bash
go build -o envoy-proxy-bouncer .                          # Build the binary
go test -race ./...                                        # Unit tests (skips functional-tagged code)
go test -tags functional -timeout 30m ./tests/functional   # Functional tests (needs Docker; 30m timeout matters — the default 10m kills the image matrix)
go test -bench=. -benchmem -run=^$ ./...                   # Benchmarks
go generate ./...                                          # Regenerate mocks — requires mockgen on PATH (go install go.uber.org/mock/mockgen@latest)
go vet ./... && gofmt -l .                                 # Lint + format check
```

Single package / single test: `go test -race ./bouncer -run TestBouncer_Check/specific_case`.
</important>

<important if="you are adding or changing a config key or env var">

- Defaults and viper wiring live in `config/config.go` — `config.GetViper(cfgFile)` returns a ready-to-use `*viper.Viper` with the env prefix (`ENVOY_BOUNCER_`), key replacer (`.`→`_`), AutomaticEnv, optional config file, and all defaults.
- When adding a config key, add the struct field in `config/` **and** a `v.SetDefault(...)` call in `GetViper`, or the zero value silently applies.
- Env vars: prefix `ENVOY_BOUNCER_` with `.`→`_` mapping (e.g. `ENVOY_BOUNCER_BOUNCER_APIKEY`); verify the exact key form against the replacer in `config/config.go`. `--config` flag accepts a yaml/json file.
- User-facing docs for config/captcha/webhooks/templates live in `docs/` — update them when changing behavior.
</important>

<important if="you are changing an interface or the mocks used in tests">

Mocks are generated with mockgen into `<pkg>/mocks/` via `//go:generate` directives next to each interface (`bouncer`, `captcha`, `types`, `server`, `pkg/crowdsec`). After changing an interface, run `go generate ./...` and commit the regenerated mocks.
</important>

<important if="you are cutting a release, tagging, or editing CI / the Helm chart">

- Push to `main` publishes a `ghcr.io/.../envoy-proxy-bouncer:sha-<sha>` image. Tagging `v*.*.*` re-tags that image, publishes the Helm chart, and runs goreleaser (skipped for `-rc` tags).
- Functional test workflow runs only on non-main pushes that touch Go files.
- Helm chart in `charts/envoy-proxy-bouncer`: `values.schema.json` (helm-values-schema-json, driven by `# @schema` comments in `values.yaml`) and chart `README.md` (helm-docs) are generated — regenerate both when editing `values.yaml`. Charts publish only from merged PRs whose branch starts with `charts/`.
</important>

<important if="you are writing or modifying any Go source">

- No comments unless asked.
- Never `else` — use early returns, or set a default value and override it conditionally.
</important>

<important if="you are writing or modifying tests">

- Use `t.Context()` for test contexts — never `context.Background()`. It is canceled when the test finishes, so it cannot leak goroutines past the test.
- testify only (`github.com/stretchr/testify`): `require` when the test cannot continue past the assertion, `assert` otherwise.
</important>

<important if="you are structuring a test file, its subtests, or fixtures">

- **Tests go in the file they test** — `recaptcha.go` is tested by `recaptcha_test.go`, never by a shared/merged test file covering multiple sources.
- **Never write mocks in test files** — every mock comes from the generated packages (`bouncer/mocks`, `captcha/mocks`, `types/mocks`, `server/mocks`, `pkg/crowdsec/mocks`, etc.); never hand-roll a mock, fake, stub, or `gomock.Matcher`. Capture and assert captured request arguments inline with `gomock.Any()` + `.Do(...)`.
- **Never use inline constructors in tests** — always call the real constructor (`New...`/`New(...)`) when one exists; never hand-assemble the struct with a literal to skip the constructor's wiring. Where a component must be substituted, construct via the real constructor first, then assign the mock to the component field directly in the test body.
- **No custom test structs** — no helper structs, `spec` tables, or wrapper types that bundle collaborators together.
- Fixture helpers are limited to wrapping a real constructor with fixed inputs (e.g. `newMetricsService(t)`) and building request payloads / expected values (`mkCheckRequest`, `wantParsed`).
- **Table-driven tests for deterministic cases** — use a table when the cases need no mocks or external setup.
- **Individual `t.Run` subtests for cases with external setup** — mocks, temp files, or other scaffolding get their own `t.Run` block; do not force them into a table.
- One distinct code path per case — no input permutations exercising identical paths; no duplicate subtests. A case that differs only in the data passed is the same code path and is redundant unless it hits a genuinely different branch.
- Assert behavior at one layer only.
</important>

<important if="you are writing assertions in a test">

- **Assertions are made in each test case** — write `assert.Equal(t, want, got)` at the call site; never extract assertions into helper functions.
- **Compare the entire `got` vs `want`** on the whole expected object, not field-by-field: entire slices, every struct field, full nested structures.
- **Explicit zero values** — write zero-value expected fields out explicitly (e.g. `Headers: nil`, `Body: nil`, `UserAgent: ""`, `wantSuccess: false`); never rely on Go's implicit zero value.
- Field-level assertions only for types with unexported or nondeterministic fields; then `assert.NotEmpty` the random field and compare the rest. No field-picking by habit.
</important>

<important if="you are writing or modifying functional tests">

- Every run executes the full CrowdSec image matrix in `tests/functional/images.go`; each image gets one shared testcontainers env reused across all subtests (avoids CrowdSec hub / Docker Hub rate limiting).
- Wait with deadline-based poll loops (`waitForServer`, `waitForDecision` in `fixtures.go`); `time.Sleep` is only acceptable for real time-based expiry (JWT/session TTL tests).
</important>
