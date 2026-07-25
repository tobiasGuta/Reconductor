package providers

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
)

func Registry(cfg config.Config) *capability.Registry {
	r := capability.NewRegistry()
	red := redaction.New(cfg.Logging.SecretNames...)
	probes := providerSpecsByName(cfg)
	subfinder := commandprovider.New(commandprovider.Definition{Name: "discover.subdomains", Description: "Discover candidate subdomains from passive roots", Provider: "subfinder", Executable: cfg.Tools.Subfinder, Version: "2", Risk: policy.Passive, ScopeType: "discovery-root", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, PassiveInput: true, OutputAdapter: "subfinder", Probe: probes["subfinder"], BuildArgs: subfinderArgs}, nil, red)
	chaos := commandprovider.New(commandprovider.Definition{Name: "discover.subdomains", Description: "Enrich candidate subdomains from ProjectDiscovery Chaos", Provider: "chaos", Executable: cfg.Tools.Chaos, Version: "2", Risk: policy.Passive, ScopeType: "discovery-root", RetrySafe: true, Idempotent: true, RequiredSecrets: []string{"CHAOS_KEY"}, Timeout: cfg.Recon.Timeout, PassiveInput: true, OutputAdapter: "chaos", Probe: probes["chaos"], BuildArgs: func(i commandprovider.Input, _ policy.Policy) ([]string, error) {
		return chaosArgs(i, cfg.Recon.ChaosKey)
	}}, nil, red)
	multi, err := capability.NewMulti("subfinder", map[string]capability.Capability{"subfinder": subfinder, "chaos": chaos})
	if err != nil {
		panic(err)
	}
	if err := r.Register(multi); err != nil {
		panic(err)
	}
	defs := []commandprovider.Definition{
		{Name: "resolve.dns", Description: "Resolve scope-authorized names", Provider: "dnsx", Executable: cfg.Tools.DNSx, Version: "3", Risk: policy.Low, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, OutputAdapter: "dnsx", Probe: probes["dnsx"], BuildInvocation: dnsxInvocation},
		{Name: "scan.ports", Description: "Discover scope-authorized network ports", Provider: "naabu", Executable: cfg.Tools.Naabu, Version: "2", Risk: policy.Low, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, OutputAdapter: "naabu", Probe: probes["naabu"], BuildArgs: func(i commandprovider.Input, p policy.Policy) ([]string, error) { return naabuArgs(i, p, cfg.Recon) }},
		{Name: "probe.http", Description: "Probe authorized HTTP services", Provider: "httpx", Executable: cfg.Tools.HTTPX, Version: "3", Risk: policy.Low, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, OutputAdapter: "httpx", Probe: probes["httpx"], BuildArgs: func(i commandprovider.Input, p policy.Policy) ([]string, error) {
			return httpxArgs(i, p, cfg.Recon)
		}},
		{Name: "crawl.web", Description: "Crawl an authorized web target", Provider: "katana", Executable: cfg.Tools.Katana, Version: "2", Risk: policy.Low, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, OutputAdapter: "katana", Probe: probes["katana"], BuildArgs: func(i commandprovider.Input, p policy.Policy) ([]string, error) {
			return katanaArgs(i, p, cfg.Recon)
		}},
		{Name: "discover.archive_urls", Description: "Discover passive archive URLs", Provider: "gau", Executable: cfg.Tools.GAU, Version: "2", Risk: policy.Passive, ScopeType: "discovery-root", RetrySafe: true, Idempotent: true, Timeout: cfg.Recon.Timeout, PassiveInput: true, OutputAdapter: "gau", Probe: probes["gau"], BuildArgs: func(i commandprovider.Input, _ policy.Policy) ([]string, error) {
			return gauArgs(i)
		}},
		{Name: "scan.nuclei", Description: "Run a policy-constrained safe Nuclei profile", Provider: "nuclei", Executable: cfg.Tools.Nuclei, Version: "2", Risk: policy.Moderate, ScopeType: "url", RetrySafe: true, Idempotent: true, Timeout: cfg.Nuclei.Timeout, OutputAdapter: "nuclei", Probe: probes["nuclei"], BuildArgs: func(i commandprovider.Input, p policy.Policy) ([]string, error) {
			return nucleiArgs(i, p, cfg.Nuclei)
		}},
	}
	for _, d := range defs {
		if err := r.Register(commandprovider.New(d, nil, red)); err != nil {
			panic(err)
		}
	}
	for _, c := range internalCapabilities() {
		if err := r.Register(c); err != nil {
			panic(err)
		}
	}
	return r
}

func subfinderArgs(i commandprovider.Input, _ policy.Policy) ([]string, error) {
	args, err := domainsArgs(i, "-d")
	if err != nil {
		return nil, err
	}
	return append(args, "-silent"), nil
}

func chaosArgs(i commandprovider.Input, key string) ([]string, error) {
	if key == "" {
		return nil, fmt.Errorf("CHAOS_KEY is required for the chaos provider")
	}
	args, err := domainsArgs(i, "-d")
	if err != nil {
		return nil, err
	}
	return append(args, "-silent"), nil
}

func naabuArgs(i commandprovider.Input, p policy.Policy, c config.Recon) ([]string, error) {
	args, err := targetHostsArgs(i, "-host")
	if err != nil {
		return nil, err
	}
	args = append(args, "-silent", "-rate", fmt.Sprint(bounded(c.RateLimit, p.RateLimit)))
	if i.Ports != "" {
		args = append(args, "-p", i.Ports)
	}
	return args, nil
}

func httpxArgs(i commandprovider.Input, p policy.Policy, c config.Recon) ([]string, error) {
	args, err := targetsArgs(i, "-u")
	if err != nil {
		return nil, err
	}
	return append(args, "-silent", "-json", "-status-code", "-content-type", "-location", "-tech-detect", "-threads", fmt.Sprint(bounded(c.Concurrency, p.Concurrency))), nil
}

func katanaArgs(i commandprovider.Input, p policy.Policy, c config.Recon) ([]string, error) {
	args, err := targetsArgs(i, "-u")
	if err != nil {
		return nil, err
	}
	args = append(args, "-silent", "-jsonl", "-fs", "fqdn", "-rate-limit", fmt.Sprint(bounded(c.RateLimit, p.RateLimit)), "-concurrency", fmt.Sprint(bounded(c.Concurrency, hostConcurrency(p))))
	if i.Headless {
		args = append(args, "-headless")
	}
	return args, nil
}

func gauArgs(i commandprovider.Input) ([]string, error) {
	domains := append([]string{}, i.Domains...)
	if i.Domain != "" {
		domains = append(domains, i.Domain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains are required")
	}
	return append([]string{"--json"}, domains...), nil
}

func nucleiArgs(i commandprovider.Input, p policy.Policy, c config.Nuclei) ([]string, error) {
	args, err := targetsArgs(i, "-u")
	if err != nil {
		return nil, err
	}
	args = append(args, "-jsonl", "-silent", "-dr", "-rl", fmt.Sprint(bounded(c.RateLimit, p.RateLimit)), "-c", fmt.Sprint(bounded(c.TemplateConcurrency, p.Concurrency)), "-bulk-size", fmt.Sprint(bounded(c.HostConcurrency, hostConcurrency(p))), "-headc", fmt.Sprint(bounded(c.HeadlessConcurrency, p.Concurrency)), "-severity", strings.Join(c.Severity, ","), "-tags", strings.Join(c.IncludeTags, ","), "-etags", strings.Join(c.ExcludeTags, ","))
	if c.TemplateDirectory != "" {
		args = append(args, "-t", c.TemplateDirectory)
	}
	return args, nil
}
func targetsArgs(i commandprovider.Input, flag string) ([]string, error) {
	if len(i.Targets) == 0 {
		return nil, fmt.Errorf("targets are required")
	}
	args := make([]string, 0, len(i.Targets)*2)
	for _, t := range i.Targets {
		args = append(args, flag, t)
	}
	return args, nil
}
func targetHostsArgs(i commandprovider.Input, flag string) ([]string, error) {
	hosts, err := normalizedTargetHosts(i.Targets)
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, len(hosts)*2)
	for _, host := range hosts {
		args = append(args, flag, host)
	}
	return args, nil
}
func dnsxInvocation(i commandprovider.Input, _ policy.Policy) (commandprovider.Invocation, error) {
	hosts, err := normalizedTargetHosts(i.Targets)
	if err != nil {
		return commandprovider.Invocation{}, err
	}
	return commandprovider.Invocation{Args: []string{"-silent"}, Stdin: []byte(strings.Join(hosts, "\n") + "\n")}, nil
}
func normalizedTargetHosts(targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets are required")
	}
	seen := map[string]bool{}
	for _, target := range targets {
		u, err := url.Parse(target)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("target %q must be an HTTP URL", target)
		}
		host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		}
		if host == "" {
			return nil, fmt.Errorf("target %q has an invalid hostname", target)
		}
		seen[host] = true
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, nil
}
func domainsArgs(i commandprovider.Input, flag string) ([]string, error) {
	domains := append([]string{}, i.Domains...)
	if i.Domain != "" {
		domains = append(domains, i.Domain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains are required")
	}
	args := make([]string, 0, len(domains)*2)
	for _, domain := range domains {
		args = append(args, flag, domain)
	}
	return args, nil
}

func bounded(configured, policyLimit int) int {
	if policyLimit > 0 && policyLimit < configured {
		return policyLimit
	}
	return configured
}

func hostConcurrency(p policy.Policy) int {
	if p.HostConcurrency > 0 {
		return p.HostConcurrency
	}
	return p.Concurrency
}
