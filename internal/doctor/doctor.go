package doctor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/providercheck"
	"github.com/tobiasGuta/Reconductor/internal/providers"
)

var ErrUnhealthy = errors.New("required environment checks failed")

type Report struct {
	CheckedAt time.Time              `json:"checked_at"`
	Healthy   bool                   `json:"healthy"`
	Results   []providercheck.Result `json:"results"`
}

func Run(ctx context.Context, cfg config.Config, configErr error) Report {
	report := Report{CheckedAt: time.Now().UTC(), Healthy: true}
	if configErr != nil {
		report.Results = append(report.Results, providercheck.Result{Component: "Configuration", Kind: "configuration", Required: true, Status: providercheck.Incompatible, Details: configErr.Error()})
	}
	report.Results = append(report.Results, CheckProviderEnvironment(ctx, cfg, nil)...)
	report.Results = append(report.Results, checkPostgreSQL(ctx, cfg), checkPreparedEvidence(ctx, cfg), checkRedis(ctx, cfg))
	report.Healthy = len(Failures(report.Results, false)) == 0
	return report
}

func CheckProviderEnvironment(ctx context.Context, cfg config.Config, runner providercheck.Runner) []providercheck.Result {
	results := make([]providercheck.Result, 0, len(providers.ExternalProviderSpecs(cfg))+1)
	for _, spec := range providers.ExternalProviderSpecs(cfg) {
		results = append(results, providercheck.Check(ctx, spec, runner))
	}
	results = append(results, checkTemplates(ctx, cfg.Nuclei.TemplateDirectory, cfg.Tools.Nuclei, runner))
	return results
}

func Failures(results []providercheck.Result, includeOptional bool) []providercheck.Result {
	var failures []providercheck.Result
	for _, result := range results {
		if !includeOptional && !result.Required {
			continue
		}
		if !successful(result.Status) {
			failures = append(failures, result)
		}
	}
	return failures
}

func WriteTable(w io.Writer, report Report) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "COMPONENT\tREQUIRED\tSTATUS\tDETECTED\tEXPECTED\tDETAILS"); err != nil {
		return err
	}
	for _, result := range report.Results {
		required := "no"
		if result.Required {
			required = "yes"
		}
		details := result.Details
		if result.Path != "" {
			if details != "" {
				details += "; "
			}
			details += result.Path
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", result.Component, required, result.Status, dash(result.DetectedVersion), dash(result.ExpectedVersion), dash(details)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func WriteJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

var nucleiTemplatesVersionPattern = regexp.MustCompile(`(?i)nuclei-templates version:\s*(v?\d+\.\d+\.\d+)(?:\s*\(([^)]+)\))?`)

func checkTemplates(ctx context.Context, root, nucleiExecutable string, runner providercheck.Runner) providercheck.Result {
	result := providercheck.Result{Component: "Nuclei templates", Kind: "templates", Required: true, ExpectedVersion: providers.TemplatesPinnedVersion}
	root = strings.TrimSpace(root)
	if root != "" {
		abs, err := filepath.Abs(root)
		if err != nil {
			result.Status = providercheck.Missing
			result.Details = safeError(err)
			return result
		}
		result.Path = abs
		info, err := os.Stat(abs)
		if err != nil || !info.IsDir() {
			result.Status = providercheck.Missing
			result.Details = "template directory is unavailable"
			return result
		}
		if marker, err := os.ReadFile(filepath.Join(abs, ".platform-template-version")); err == nil {
			return evaluateTemplateVersion(result, strings.TrimSpace(string(marker)), "template snapshot marker")
		}
	}

	if runner == nil {
		runner = providercheck.OSRunner{}
	}
	path, err := runner.LookPath(nucleiExecutable)
	if err != nil {
		result.Status = providercheck.Missing
		result.Details = "nuclei is required to discover the standard template directory"
		return result
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, probeErr := runner.CombinedOutput(probeCtx, path, []string{"-tv"})
	if probeCtx.Err() != nil {
		probeErr = probeCtx.Err()
	}
	detectedVersion, detectedPath := parseNucleiTemplatesVersion(output)
	if detectedPath != "" {
		result.Path = detectedPath
	}
	if probeErr != nil {
		result.Status = providercheck.Status("untracked")
		result.Details = "nuclei template version probe failed: " + safeError(probeErr)
		return result
	}
	if detectedVersion == "" {
		result.Status = providercheck.Status("untracked")
		result.Details = "nuclei -tv did not report a template version"
		return result
	}
	if root != "" && detectedPath == "" {
		result.Status = providercheck.Status("untracked")
		result.DetectedVersion = detectedVersion
		result.Details = "nuclei -tv did not report the active template directory"
		return result
	}
	if root != "" && detectedPath != "" && !samePath(root, detectedPath) {
		result.Status = providercheck.Status("untracked")
		result.DetectedVersion = detectedVersion
		result.Details = "NUCLEI_TEMPLATE_DIR differs from nuclei's active template directory"
		return result
	}
	return evaluateTemplateVersion(result, detectedVersion, "nuclei -tv")
}

func parseNucleiTemplatesVersion(output string) (string, string) {
	match := nucleiTemplatesVersionPattern.FindStringSubmatch(output)
	if len(match) == 0 {
		return "", ""
	}
	version := match[1]
	if !strings.HasPrefix(strings.ToLower(version), "v") {
		version = "v" + version
	}
	path := ""
	if len(match) > 2 {
		path = strings.TrimSpace(match[2])
	}
	return version, path
}

func evaluateTemplateVersion(result providercheck.Result, version, source string) providercheck.Result {
	result.DetectedVersion = version
	switch compareVersion(version, providers.TemplatesPinnedVersion) {
	case -1:
		result.Status = providercheck.Status("outdated")
		result.Details = source + " is older than the platform pin"
	case 0:
		result.Status = providercheck.Status("current")
		result.Details = source + " matches the platform pin"
	case 1:
		result.Status = providercheck.Status("ahead")
		result.Details = source + " is newer than the worker pin"
	default:
		result.Status = providercheck.Status("untracked")
		result.Details = source + " does not contain a comparable version"
	}
	return result
}

func compareVersion(a, b string) int {
	left, ok := parseVersionParts(a)
	if !ok {
		return 2
	}
	right, ok := parseVersionParts(b)
	if !ok {
		return 2
	}
	for i := range left {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return 0
}

func parseVersionParts(version string) ([3]int, bool) {
	var parts [3]int
	version = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(version)), "v")
	values := strings.Split(version, ".")
	if len(values) != 3 {
		return parts, false
	}
	for i, value := range values {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return parts, false
		}
		parts[i] = parsed
	}
	return parts, true
}

func samePath(a, b string) bool {
	absA, err := filepath.Abs(a)
	if err == nil {
		a = absA
	}
	absB, err := filepath.Abs(b)
	if err == nil {
		b = absB
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func successful(status providercheck.Status) bool {
	switch status {
	case providercheck.Compatible, providercheck.Status("current"), providercheck.Status("ahead"), providercheck.Status("reachable"):
		return true
	default:
		return false
	}
}

func dash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.Join(strings.Fields(err.Error()), " ")
	if len(value) > 1024 {
		value = value[:1024]
	}
	return value
}

func checkPostgreSQL(ctx context.Context, cfg config.Config) providercheck.Result {
	result := providercheck.Result{Component: "PostgreSQL", Kind: "service", Required: true, ExpectedVersion: ">=15"}
	if strings.TrimSpace(cfg.Database.URL) == "" {
		result.Status = providercheck.Status("not_configured")
		result.Details = "DATABASE_URL is required"
		return result
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	store, err := database.Open(checkCtx, cfg.Database.URL)
	if err != nil {
		result.Status = providercheck.Status("unreachable")
		result.Details = safeError(err)
		return result
	}
	defer store.Close()
	var version string
	if err := store.Pool.QueryRow(checkCtx, `SHOW server_version`).Scan(&version); err != nil {
		result.Status = providercheck.Status("unreachable")
		result.Details = safeError(err)
		return result
	}
	result.DetectedVersion = version
	major, _ := strconv.Atoi(strings.SplitN(version, ".", 2)[0])
	if major < 15 {
		result.Status = providercheck.Incompatible
		result.Details = "database server is older than the supported major version"
		return result
	}
	result.Status = providercheck.Status("reachable")
	result.Details = "connection and version query succeeded"
	return result
}

func checkPreparedEvidence(ctx context.Context, cfg config.Config) providercheck.Result {
	result := providercheck.Result{Component: "Prepared evidence", Kind: "artifact_store", Required: true, ExpectedVersion: "configured with admission capacity"}
	if strings.TrimSpace(cfg.Database.URL) == "" {
		result.Status = providercheck.Status("not_configured")
		result.Details = "DATABASE_URL is required to validate prepared evidence"
		return result
	}
	storeID, err := cfg.ArtifactStorage.RequiredStoreID()
	if err != nil {
		result.Status = providercheck.Status("not_configured")
		result.Details = safeError(err)
		return result
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	store, err := database.Open(checkCtx, cfg.Database.URL)
	if err != nil {
		result.Status = providercheck.Status("unreachable")
		result.Details = safeError(err)
		return result
	}
	defer store.Close()
	if err := store.RequireCurrentSchema(checkCtx); err != nil {
		result.Status = providercheck.Incompatible
		result.Details = safeError(err)
		return result
	}
	local, err := artifact.OpenLocal(checkCtx, cfg.ArtifactStorage.Root, storeID, store, nil)
	if err != nil {
		result.Status = providercheck.Incompatible
		result.Details = safeError(err)
		return result
	}
	guard, err := local.AcquirePublisher(checkCtx, local.Identity())
	if err != nil {
		result.Status = providercheck.Incompatible
		result.Details = safeError(err)
		return result
	}
	if _, ok := guard.(artifact.PreparedPublisherGuard); !ok {
		_ = guard.Close()
		result.Status = providercheck.Incompatible
		result.Details = "artifact publisher lacks prepared-evidence capability"
		return result
	}
	if err := guard.Close(); err != nil {
		result.Status = providercheck.Incompatible
		result.Details = safeError(err)
		return result
	}
	status, err := store.RequirePreparedEvidenceReady(checkCtx, storeID)
	if err != nil {
		result.Status = providercheck.Incompatible
		result.Details = safeError(err)
		return result
	}
	result.Status = providercheck.Status("reachable")
	result.Path = cfg.ArtifactStorage.Root
	result.Details = fmt.Sprintf("durable publisher ready; open sets %d/%d; unresolved bytes %d/%d; per-set reservation %d", status.OpenSets, status.MaxOpenSets, status.UnresolvedBytes, status.MaxUnresolvedBytes, status.MaxSetBytes)
	return result
}

func checkRedis(ctx context.Context, cfg config.Config) providercheck.Result {
	result := providercheck.Result{Component: "Redis", Kind: "service", Required: true, ExpectedVersion: ">=7"}
	if !strings.Contains(cfg.Redis.Address, ":") {
		result.Status = providercheck.Status("not_configured")
		result.Details = "REDIS_ADDR must be host:port"
		return result
	}
	probe, err := net.DialTimeout("tcp", cfg.Redis.Address, 2*time.Second)
	if err != nil {
		result.Status = providercheck.Status("unreachable")
		result.Details = safeError(err)
		return result
	}
	_ = probe.Close()
	opts := &redis.Options{Addr: cfg.Redis.Address, Username: cfg.Redis.Username, Password: cfg.Redis.Password, DB: cfg.Redis.DB, DialTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxRetries: -1, DisableIdentity: true, MaintNotificationsConfig: &maintnotifications.Config{Mode: maintnotifications.ModeDisabled}}
	if cfg.Redis.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(opts)
	defer client.Close()
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(checkCtx).Err(); err != nil {
		result.Status = providercheck.Status("unreachable")
		result.Details = safeError(err)
		return result
	}
	info, err := client.Info(checkCtx, "server").Result()
	if err != nil {
		result.Status = providercheck.Status("unreachable")
		result.Details = safeError(err)
		return result
	}
	for _, line := range strings.Split(info, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "redis_version:"); ok {
			result.DetectedVersion = value
			break
		}
	}
	major, _ := strconv.Atoi(strings.SplitN(result.DetectedVersion, ".", 2)[0])
	if major < 7 {
		result.Status = providercheck.Incompatible
		result.Details = "Redis server is older than the supported major version"
		return result
	}
	result.Status = providercheck.Status("reachable")
	result.Details = "PING and server information query succeeded"
	return result
}
