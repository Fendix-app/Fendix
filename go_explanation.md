# Go Explanation for Python/Django/FastAPI Developers

## The Big Picture

This is a **security scanner** (like a Go-based ZAP/Burp). The `engine` package is the orchestrator — think of it like a Django management command or a FastAPI background task that coordinates: discover endpoints → run security checks concurrently → collect results → generate a report.

---

## File-by-File Breakdown

### 1. `engine.go` — Package Documentation

```go
package engine
```

This is just a doc comment + package declaration. In Python terms, this is like a docstring at the top of `__init__.py`. Every `.go` file in the same directory **must** declare the same package name — they all merge into one namespace (unlike Python where each file is its own module).

**Key Go concept: Packages ≠ Files.** In Python, `engine/orchestrator.py` and `engine/workerpool.py` are separate modules. In Go, `engine/orchestrator.go` and `engine/workerpool.go` are the **same package** — all functions/types are accessible to each other without imports, as if they were in one file.

---

### 2. `finding.go` — Core Data Types

```go
type Severity string

const (
    SeverityCritical Severity = "CRITICAL"
    SeverityHigh     Severity = "HIGH"
    ...
)
```

**Python equivalent:**
```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
```

Go doesn't have enums. Instead, you create a **named type** (`type Severity string`) and define constants of that type. The type system prevents you from passing a random string where a `Severity` is expected (unlike raw strings, but weaker than Python Enums — no `.name`, no iteration).

---

```go
type Finding struct {
    ID         string     `json:"id"`
    Title      string     `json:"title"`
    Severity   Severity   `json:"severity"`
    Line       *string    `json:"line"`
    References []string   `json:"references"`
}
```

**Python equivalent:**
```python
@dataclass  # or Pydantic BaseModel
class Finding:
    id: str
    title: str
    severity: Severity
    line: Optional[str] = None
    references: list[str]
```

Key things:

- **Struct = dataclass/Pydantic model.** It's a typed container of fields. No methods by default (you add them separately).
- **`` `json:"id"` `` = struct tags.** These are metadata annotations, like Pydantic's `Field(alias="id")`. Go's `encoding/json` reads them at runtime via reflection to know how to serialize/deserialize.
- **`*string`** = pointer to string = **`Optional[str]`**. A regular `string` in Go can never be `nil` (zero value is `""`). A `*string` can be `nil`, which maps to JSON `null`. This is how Go does "nullable" fields.
- **`[]string`** = a **slice** = Python `list[str]`. Slices are Go's dynamic arrays.

---

```go
func SeverityRank(s Severity) int {
    switch s {
    case SeverityCritical:
        return 4
    ...
    default:
        return 0
    }
}
```

This is a **standalone function**, not a method on the type. Python equivalent:

```python
def severity_rank(s: Severity) -> int:
    return {"CRITICAL": 4, "HIGH": 3, ...}.get(s, 0)
```

`switch` in Go = `match` in Python 3.10+ (or `if/elif` chains). No `break` needed — Go `switch` doesn't fall through by default (opposite of C).

---

### 3. `config.go` — Configuration

```go
type AuthContext struct {
    Type   string
    Value  string
    Header string
}

type ScanConfig struct {
    URL       string
    Auth      *AuthContext
    AuthUser2 *AuthContext
    Workers   int
    ...
}
```

**Python equivalent:**
```python
class ScanConfig(BaseModel):
    url: str
    auth: Optional[AuthContext] = None
    auth_user2: Optional[AuthContext] = None
    workers: int
```

Notice `Auth *AuthContext` — the pointer (`*`) means this field is optional/nullable. If no auth is provided, it's `nil` (Python's `None`). A non-pointer struct field is always initialized with zero values (empty strings, 0 ints), never nil.

**Go naming convention:** `PascalCase` = exported (public), `camelCase` = unexported (private). This replaces Python's `_` prefix convention. `ScanConfig` is public; a hypothetical `scanConfig` would be package-private.

---

### 4. `scanner.go` — Check Interface

```go
type CheckFn func(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding
```

This is a **function type** — it defines a signature. Python equivalent:

```python
CheckFn = Callable[[ScanConfig, Endpoint], list[Finding]]
```

In Go, functions are first-class values. You can store them in slices, pass them around. This is how the scanner achieves polymorphism **without interfaces or classes** — each check (headers, CORS, auth, etc.) is just a function with this signature.

The `context.Context` parameter is Go's way of handling **cancellation and timeouts** — think of it as Python's `asyncio.CancelledError` or Django's request lifecycle, but explicit. Every long-running operation takes a `ctx` as its first parameter. If the user hits Ctrl+C, `ctx.Done()` fires and goroutines can clean up.

---

### 5. `orchestrator.go` — The Main Pipeline

```go
type Orchestrator struct {
    cfg *models.ScanConfig
}

func NewOrchestrator(cfg *models.ScanConfig) *Orchestrator {
    return &Orchestrator{cfg: cfg}
}
```

**Python equivalent:**
```python
class Orchestrator:
    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
```

Go has **no constructors**. By convention, you write a `NewXxx` function that returns a pointer to the struct. `&Orchestrator{cfg: cfg}` creates the struct on the heap and returns its address. Think `&` = "give me a pointer to this" (like passing by reference).

---

#### The `Run` method — the heart of the scanner:

```go
func (o *Orchestrator) Run(ctx context.Context) int {
```

**`(o *Orchestrator)`** is the **receiver** — this is how Go does methods. It's equivalent to `self` in Python:

```python
def run(self, ctx) -> int:
```

The `*` means the receiver is a pointer (can modify the struct). Without `*`, Go would copy the entire struct on every call (value semantics).

**The pipeline steps:**

| Step | Go Code | Python Analogy |
|------|---------|----------------|
| 1. Discover | `crawler.CrawlEndpoints(ctx)` | `await crawler.crawl()` |
| 2. Build checks | `checks := []scanner.CheckFn{...}` | `checks = [check_headers, check_cors, ...]` |
| 3. Run concurrently | `pool.Run(ctx, cfg, endpoints)` | `asyncio.gather(*tasks)` or `ThreadPoolExecutor` |
| 4. Sort | `sort.Slice(findings, func(i, j int) bool {...})` | `findings.sort(key=lambda f: (f.endpoint, f.category, f.title))` |
| 5. Assign IDs | `findings[i].ID = fmt.Sprintf("SEC-%03d", i+1)` | `f.id = f"SEC-{i+1:03d}"` |
| 6. Sanitize | `reporters.SanitizeFindings(...)` | Strip credentials from output |
| 7. Render | `o.renderReport(...)` | Write JSON/HTML |
| 8. Exit code | `o.checkFailOn(findings)` | `sys.exit(1)` if severity threshold met |

**Key Go patterns here:**

```go
endpoints, err := crawler.CrawlEndpoints(ctx)
if err != nil {
    slog.Error("endpoint discovery failed", "error", err)
    return 2
}
```

**Go error handling = explicit return values, not exceptions.** Functions return `(result, error)` tuples. You MUST check `err != nil` after every call. There's no `try/except`. This is the most jarring difference from Python — every error is handled at the call site.

Python equivalent:
```python
try:
    endpoints = crawler.crawl_endpoints()
except Exception as e:
    logger.error(f"endpoint discovery failed: {e}")
    return 2
```

```go
slog.Info("scanning endpoints", "count", len(endpoints))
```

`slog` is Go's structured logger (stdlib since Go 1.21). Like Python's `structlog` or `logging.info("...", extra={"count": n})`. Key-value pairs, not format strings.

---

#### `renderReport` — output routing

```go
var w io.Writer = os.Stdout
if o.cfg.OutputPath != "" {
    f, err := os.Create(o.cfg.OutputPath)
    ...
    defer f.Close()
    w = f
}
```

**`io.Writer`** is an **interface** — Go's most important concept. It's like Python's `Protocol` or duck typing, but compile-time checked:

```go
type Writer interface {
    Write(p []byte) (n int, err error)
}
```

Anything with a `Write` method satisfies `io.Writer`. Both `os.Stdout` and `*os.File` implement it. This is Go's version of polymorphism — **no inheritance, no ABC, just "does it have the right methods?"**

**`defer f.Close()`** = Python's context manager (`with open(...) as f:`). `defer` schedules a function call to run when the enclosing function returns. It's stack-based (LIFO), guaranteed to run even on error/panic.

---

### 6. `workerpool.go` — Concurrency

This is where Go really shines vs Python (no GIL!).

```go
jobs := make(chan scanJob, len(endpoints)*len(wp.checks))
results := make(chan []models.Finding, len(endpoints)*len(wp.checks))
```

**Channels** = Go's concurrency primitive. Think of them as `asyncio.Queue` or `queue.Queue` for threads. `chan scanJob` is a typed queue that goroutines use to communicate.

- `make(chan T, bufferSize)` — buffered channel (won't block until full)
- Writing: `jobs <- scanJob{...}` (like `queue.put()`)
- Reading: `for job := range jobs` (like `while item := queue.get()`)

```go
var wg sync.WaitGroup
for i := 0; i < wp.workers; i++ {
    wg.Add(1)
    go func(workerID int) {
        defer wg.Done()
        for job := range jobs {
            ...
        }
    }(i)
}
```

**`go func() { ... }()`** = launches a **goroutine**. This is Go's killer feature. Goroutines are like ultra-lightweight threads (~2KB stack vs ~8MB for OS threads). You can spawn thousands easily.

Python equivalent (roughly):
```python
with ThreadPoolExecutor(max_workers=workers) as pool:
    futures = [pool.submit(check, endpoint) for ...]
```

**`sync.WaitGroup`** = a counter to wait for goroutines to finish. Like Python's `asyncio.gather()` or `concurrent.futures.wait()`:
- `wg.Add(1)` — "one more goroutine started"
- `wg.Done()` — "one goroutine finished" (via `defer` — always runs)
- `wg.Wait()` — "block until counter is 0"

```go
select {
case <-ctx.Done():
    return
default:
}
```

**`select`** = `switch` but for channels. It checks if cancellation was requested (`ctx.Done()` fires). The `default` case makes it non-blocking — "if no cancellation, continue". This is how Go handles cooperative cancellation inside goroutines.

---

The **fan-out/fan-in pattern** here:

```
                    ┌─ worker 0 ─┐
jobs channel ──────►├─ worker 1 ─┤──────► results channel ──► collect
                    └─ worker 2 ─┘
```

1. **Fan-out**: Jobs are pushed into the `jobs` channel, N workers consume them
2. **Fan-in**: Workers push findings into the `results` channel
3. **Collect**: The main goroutine reads all results after workers finish

The `go func() { wg.Wait(); close(results) }()` pattern is idiomatic — a goroutine that waits for all workers, then closes the results channel so the `for batch := range results` loop terminates.

---

## Go Module Path

```
module github.com/Fendix-app/Fendix/go
```

This is the module's **identity** defined in `go.mod`, used for all imports. It's like the `name` field in `pyproject.toml`. When you see:

```go
import "github.com/Fendix-app/Fendix/go/internal/models"
```

That resolves to the local directory `go/internal/models/` — not a network request. The GitHub-style path is a convention for global uniqueness and enables `go get` to fetch it if published.

**Key difference from Python:** All Go imports are **absolute** from the module root — there are no relative imports.

---

## Go vs Python Mental Model Summary

| Concept | Python | Go |
|---------|--------|----|
| Class | `class Foo:` | `type Foo struct{}` + methods with receivers |
| Constructor | `__init__` | `NewFoo()` function |
| self | `self.x` | `(f *Foo)` receiver |
| Optional | `Optional[str]` | `*string` (pointer) |
| Enum | `class X(Enum)` | `type X string` + `const` block |
| Error handling | `try/except` | `if err != nil` |
| Async/concurrency | `asyncio` / `ThreadPoolExecutor` | goroutines + channels |
| Context manager | `with open() as f:` | `defer f.Close()` |
| Duck typing | Protocols / ABC | Interfaces |
| Public/private | `_` prefix convention | PascalCase / camelCase |
| Package | one file = one module | all files in a dir = one package |
| List | `list[str]` | `[]string` (slice) |
| Dict | `dict[str, int]` | `map[string]int` |
| f-strings | `f"SEC-{i:03d}"` | `fmt.Sprintf("SEC-%03d", i)` |
| `internal/` | not a thing | **enforced by compiler** — only parent module can import |

The `internal/` directory is special in Go: code in `github.com/Fendix-app/Fendix/go/internal/...` can **only** be imported by code rooted at `github.com/Fendix-app/Fendix/go/`. The compiler enforces this. It's like having truly private packages.
