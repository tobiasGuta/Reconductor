package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/policy"
)

type Config struct {
	Database        Database
	Redis           Redis
	Tools           Tools
	Recon           Recon
	Worker          Worker
	Scheduler       Scheduler
	Nuclei          Nuclei
	ArtifactStorage ArtifactStorage
	Policy          Policy
	Logging         Logging
}

type Database struct{ URL string }
type Tools struct {
	Subfinder string
	Chaos     string
	DNSx      string
	Naabu     string
	HTTPX     string
	Katana    string
	GAU       string
	Nuclei    string
}
type Redis struct {
	Address  string
	Username string
	Password string
	DB       int
	TLS      bool
}
type Recon struct {
	Pipeline       string
	Headless       bool
	ChaosKey       string
	Timeout        time.Duration
	RateLimit      int
	Concurrency    int
	ProviderUpdate bool
}
type Worker struct {
	ConsumerGroup string
	ConsumerName  string
	PoolSize      int
	LeaseTimeout  time.Duration
	ReadBlock     time.Duration
	MaxRetries    int
	RetryBase     time.Duration
}
type Scheduler struct {
	PollInterval      time.Duration
	MaxConcurrentRuns int
	LeaseTimeout      time.Duration
	WorkflowStateRoot string
}
type Nuclei struct {
	RateLimit           int
	HostConcurrency     int
	TemplateConcurrency int
	HeadlessConcurrency int
	Timeout             time.Duration
	Severity            []string
	IncludeTags         []string
	ExcludeTags         []string
	TemplateDirectory   string
	UpdateTemplates     bool
}
type ArtifactStorage struct {
	Driver string
	Root   string
}
type Policy struct {
	DefaultRateLimit           int
	DefaultConcurrency         int
	DefaultProviderConcurrency int
	DefaultHostConcurrency     int
	MaxPayloadBytes            int64
	AllowedMethods             []string
	FollowRedirects            bool
	ScanWindows                []string
	AuthenticationUsage        bool
	DirectoryFuzzing           bool
	CrossOrigin                bool
	IntrusiveChecks            bool
	ArtifactRetention          time.Duration
}
type Logging struct {
	Level       string
	SecretNames []string
}

type Lookup func(string) string

func Load() (Config, error)         { return LoadWith(os.Getenv) }
func LoadPlanning() (Config, error) { return loadWith(os.Getenv, false) }
func LoadDoctor() (Config, error)   { return loadWith(os.Getenv, false) }

func LoadWith(get Lookup) (Config, error) {
	return loadWith(get, true)
}

func loadWith(get Lookup, requireDatabase bool) (Config, error) {
	c := Config{
		Database:        Database{URL: get("DATABASE_URL")},
		Redis:           Redis{Address: value(get, "REDIS_ADDR", "localhost:6379"), Username: get("REDIS_USERNAME"), Password: get("REDIS_PASSWORD"), DB: integer(get, "REDIS_DB", 0), TLS: boolean(get, "REDIS_TLS", false)},
		Tools:           Tools{Subfinder: value(get, "SUBFINDER_EXECUTABLE", "subfinder"), Chaos: value(get, "CHAOS_EXECUTABLE", "chaos"), DNSx: value(get, "DNSX_EXECUTABLE", "dnsx"), Naabu: value(get, "NAABU_EXECUTABLE", "naabu"), HTTPX: value(get, "HTTPX_EXECUTABLE", "httpx"), Katana: value(get, "KATANA_EXECUTABLE", "katana"), GAU: value(get, "GAU_EXECUTABLE", "gau"), Nuclei: value(get, "NUCLEI_EXECUTABLE", "nuclei")},
		Recon:           Recon{Pipeline: value(get, "RECON_PIPELINE", "sdnhkga"), Headless: boolean(get, "RECON_HEADLESS", false), ChaosKey: get("CHAOS_KEY"), Timeout: duration(get, "RECON_TIMEOUT", 15*time.Minute), RateLimit: integer(get, "RECON_RATE_LIMIT", 75), Concurrency: integer(get, "RECON_CONCURRENCY", 20), ProviderUpdate: boolean(get, "RECON_PROVIDER_UPDATE", false)},
		Worker:          Worker{ConsumerGroup: value(get, "WORKER_CONSUMER_GROUP", "capability-workers"), ConsumerName: value(get, "WORKER_CONSUMER_NAME", hostname()), PoolSize: integer(get, "WORKER_POOL_SIZE", 4), LeaseTimeout: duration(get, "WORKER_LEASE_TIMEOUT", 2*time.Minute), ReadBlock: duration(get, "WORKER_READ_BLOCK", 5*time.Second), MaxRetries: integer(get, "WORKER_MAX_RETRIES", 3), RetryBase: duration(get, "WORKER_RETRY_BASE", 2*time.Second)},
		Scheduler:       Scheduler{PollInterval: duration(get, "SCHEDULER_POLL_INTERVAL", 15*time.Second), MaxConcurrentRuns: integer(get, "SCHEDULER_MAX_CONCURRENT_RUNS", 1), LeaseTimeout: duration(get, "SCHEDULER_LEASE_TIMEOUT", 2*time.Minute), WorkflowStateRoot: value(get, "WORKFLOW_STATE_ROOT", "state/runs")},
		Nuclei:          Nuclei{RateLimit: integer(get, "NUCLEI_RATE_LIMIT", 50), HostConcurrency: integer(get, "NUCLEI_HOST_CONCURRENCY", 10), TemplateConcurrency: integer(get, "NUCLEI_TEMPLATE_CONCURRENCY", 10), HeadlessConcurrency: integer(get, "NUCLEI_HEADLESS_CONCURRENCY", 2), Timeout: duration(get, "NUCLEI_TIMEOUT", 10*time.Minute), Severity: csv(get, "NUCLEI_SEVERITY", "low,medium,high,critical"), IncludeTags: csv(get, "NUCLEI_INCLUDE_TAGS", "cve,exposure,misconfig"), ExcludeTags: csv(get, "NUCLEI_EXCLUDE_TAGS", "dos,fuzz,bruteforce,intrusive"), TemplateDirectory: get("NUCLEI_TEMPLATE_DIR"), UpdateTemplates: boolean(get, "NUCLEI_UPDATE_TEMPLATES", false)},
		ArtifactStorage: ArtifactStorage{Driver: value(get, "ARTIFACT_DRIVER", "local"), Root: value(get, "ARTIFACT_ROOT", "artifacts")},
		Policy:          Policy{DefaultRateLimit: integer(get, "POLICY_RATE_LIMIT", 50), DefaultConcurrency: integer(get, "POLICY_CONCURRENCY", 10), DefaultProviderConcurrency: integer(get, "POLICY_PROVIDER_CONCURRENCY", 2), DefaultHostConcurrency: integer(get, "POLICY_HOST_CONCURRENCY", 1), MaxPayloadBytes: int64(integer(get, "POLICY_MAX_PAYLOAD_BYTES", 1048576)), AllowedMethods: csv(get, "POLICY_ALLOWED_METHODS", "GET,HEAD,OPTIONS"), FollowRedirects: boolean(get, "POLICY_FOLLOW_REDIRECTS", false), ScanWindows: csv(get, "POLICY_SCAN_WINDOWS", ""), AuthenticationUsage: boolean(get, "POLICY_AUTHENTICATION_USAGE", false), DirectoryFuzzing: boolean(get, "POLICY_DIRECTORY_FUZZING", false), CrossOrigin: boolean(get, "POLICY_CROSS_ORIGIN", false), IntrusiveChecks: boolean(get, "POLICY_INTRUSIVE_CHECKS", false), ArtifactRetention: duration(get, "POLICY_ARTIFACT_RETENTION", 720*time.Hour)},
		Logging:         Logging{Level: value(get, "LOG_LEVEL", "info"), SecretNames: csv(get, "REDACT_SECRET_NAMES", "")},
	}
	var parseErrs []error
	for _, key := range []string{"REDIS_TLS", "RECON_HEADLESS", "RECON_PROVIDER_UPDATE", "NUCLEI_UPDATE_TEMPLATES", "POLICY_FOLLOW_REDIRECTS", "POLICY_AUTHENTICATION_USAGE", "POLICY_DIRECTORY_FUZZING", "POLICY_CROSS_ORIGIN", "POLICY_INTRUSIVE_CHECKS"} {
		if v := strings.TrimSpace(get(key)); v != "" {
			if _, err := strconv.ParseBool(v); err != nil {
				parseErrs = append(parseErrs, fmt.Errorf("%s must be true or false", key))
			}
		}
	}
	for _, key := range []string{"RECON_TIMEOUT", "WORKER_LEASE_TIMEOUT", "WORKER_READ_BLOCK", "WORKER_RETRY_BASE", "SCHEDULER_POLL_INTERVAL", "SCHEDULER_LEASE_TIMEOUT", "NUCLEI_TIMEOUT", "POLICY_ARTIFACT_RETENTION"} {
		if v := strings.TrimSpace(get(key)); v != "" {
			if _, err := time.ParseDuration(v); err != nil {
				parseErrs = append(parseErrs, fmt.Errorf("%s must be a Go duration", key))
			}
		}
	}
	return c, errors.Join(append(parseErrs, c.validate(requireDatabase))...)
}

func (c Config) Validate() error { return c.validate(true) }
func (c Config) validate(requireDatabase bool) error {
	var errs []error
	if requireDatabase && c.Database.URL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if !strings.Contains(c.Redis.Address, ":") {
		errs = append(errs, errors.New("REDIS_ADDR must be host:port"))
	}
	if c.Redis.DB < 0 {
		errs = append(errs, errors.New("REDIS_DB must be non-negative"))
	}
	if c.Recon.Timeout <= 0 || c.Recon.RateLimit < 1 || c.Recon.Concurrency < 1 {
		errs = append(errs, errors.New("recon timeout, rate limit, and concurrency must be positive"))
	}
	if c.Worker.PoolSize < 1 || c.Worker.MaxRetries < 0 {
		errs = append(errs, errors.New("worker pool must be positive and retries non-negative"))
	}
	if c.Worker.LeaseTimeout <= 0 || c.Worker.ReadBlock <= 0 {
		errs = append(errs, errors.New("worker lease and read block must be positive durations"))
	}
	if c.Worker.RetryBase <= 0 {
		errs = append(errs, errors.New("worker retry base must be positive"))
	}
	if c.Scheduler.PollInterval <= 0 || c.Scheduler.LeaseTimeout <= 0 {
		errs = append(errs, errors.New("scheduler poll interval and lease timeout must be positive durations"))
	}
	if c.Scheduler.MaxConcurrentRuns < 1 {
		errs = append(errs, errors.New("SCHEDULER_MAX_CONCURRENT_RUNS must be positive"))
	}
	if strings.TrimSpace(c.Scheduler.WorkflowStateRoot) == "" {
		errs = append(errs, errors.New("WORKFLOW_STATE_ROOT is required"))
	}
	if c.Nuclei.RateLimit < 1 || c.Nuclei.HostConcurrency < 1 || c.Nuclei.TemplateConcurrency < 1 || c.Nuclei.HeadlessConcurrency < 1 {
		errs = append(errs, errors.New("nuclei limits and concurrency values must be positive"))
	}
	if c.Nuclei.Timeout <= 0 {
		errs = append(errs, errors.New("NUCLEI_TIMEOUT must be positive"))
	}
	if c.ArtifactStorage.Driver != "local" {
		errs = append(errs, fmt.Errorf("unsupported ARTIFACT_DRIVER %q", c.ArtifactStorage.Driver))
	}
	if strings.TrimSpace(c.ArtifactStorage.Root) == "" {
		errs = append(errs, errors.New("ARTIFACT_ROOT is required"))
	}
	if c.Policy.DefaultRateLimit < 1 || c.Policy.DefaultConcurrency < 1 || c.Policy.DefaultProviderConcurrency < 1 || c.Policy.DefaultHostConcurrency < 1 || c.Policy.MaxPayloadBytes < 1 {
		errs = append(errs, errors.New("policy rate limit, concurrency, and maximum payload size must be positive"))
	}
	if len(c.Policy.AllowedMethods) == 0 {
		errs = append(errs, errors.New("at least one policy HTTP method is required"))
	}
	if c.Policy.ArtifactRetention < 0 {
		errs = append(errs, errors.New("POLICY_ARTIFACT_RETENTION must be non-negative"))
	}
	for _, window := range c.Policy.ScanWindows {
		if evaluation := policy.EvaluateAt(policy.Policy{ScanWindows: []string{window}}, "config.validate", policy.Passive, false, policy.Requirements{}, nil, time.Now().UTC()); evaluation.Decision == policy.Deny && strings.Contains(evaluation.Reason, "invalid") {
			errs = append(errs, fmt.Errorf("POLICY_SCAN_WINDOWS: %s", evaluation.Reason))
		}
	}
	allowedStages := "sdnhkga"
	for _, stage := range c.Recon.Pipeline {
		if !strings.ContainsRune(allowedStages, stage) {
			errs = append(errs, fmt.Errorf("RECON_PIPELINE contains unknown stage %q", stage))
		}
	}
	return errors.Join(errs...)
}

func (c Config) String() string {
	return fmt.Sprintf("database=<configured> redis=%s redis_password=<redacted> recon=%s worker_pool=%d nuclei_rl=%d artifacts=%s", c.Redis.Address, c.Recon.Pipeline, c.Worker.PoolSize, c.Nuclei.RateLimit, c.ArtifactStorage.Root)
}

func LoadEnvFile(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid env line %q", line)
		}
		key, val = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(val), "\"'")
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, val); err != nil {
				return err
			}
		}
	}
	return s.Err()
}

func value(get Lookup, key, fallback string) string {
	if v := strings.TrimSpace(get(key)); v != "" {
		return v
	}
	return fallback
}
func integer(get Lookup, key string, fallback int) int {
	v := get(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1
	}
	return n
}
func boolean(get Lookup, key string, fallback bool) bool {
	v := get(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}
func duration(get Lookup, key string, fallback time.Duration) time.Duration {
	v := get(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return -1
	}
	return d
}
func csv(get Lookup, key, fallback string) []string {
	raw := value(get, key, fallback)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "worker"
	}
	return h
}
