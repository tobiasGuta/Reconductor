package providers

import (
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/providercheck"
)

const (
	SubfinderPinnedVersion = "v2.14.0"
	ChaosPinnedVersion     = "v0.5.2"
	DNSxPinnedVersion      = "v1.3.0"
	NaabuPinnedVersion     = "v2.6.1"
	HTTPXPinnedVersion     = "v1.10.0"
	KatanaPinnedVersion    = "v1.6.1"
	GAUPinnedVersion       = "v2.2.4"
	NucleiPinnedVersion    = "v3.10.0"
	TemplatesPinnedVersion = "v10.4.3"
)

func ExternalProviderSpecs(cfg config.Config) []providercheck.Spec {
	return []providercheck.Spec{
		{Name: "subfinder", DisplayName: "Subfinder", Executable: cfg.Tools.Subfinder, ExecutableEnv: "SUBFINDER_EXECUTABLE", VersionArgs: providerVersionArgs(cfg), CompatiblePrefix: "2.", PinnedVersion: SubfinderPinnedVersion, Required: true},
		{Name: "chaos", DisplayName: "Chaos", Executable: cfg.Tools.Chaos, ExecutableEnv: "CHAOS_EXECUTABLE", VersionArgs: []string{"-version"}, CompatiblePrefix: "0.5.", PinnedVersion: ChaosPinnedVersion, Required: false},
		{Name: "dnsx", DisplayName: "DNSx", Executable: cfg.Tools.DNSx, ExecutableEnv: "DNSX_EXECUTABLE", VersionArgs: providerVersionArgs(cfg), CompatiblePrefix: "1.", PinnedVersion: DNSxPinnedVersion, Required: true},
		{Name: "naabu", DisplayName: "Naabu", Executable: cfg.Tools.Naabu, ExecutableEnv: "NAABU_EXECUTABLE", VersionArgs: providerVersionArgs(cfg), CompatiblePrefix: "2.", PinnedVersion: NaabuPinnedVersion, Required: true},
		{Name: "httpx", DisplayName: "HTTPX", Executable: cfg.Tools.HTTPX, ExecutableEnv: "HTTPX_EXECUTABLE", VersionArgs: providerVersionArgs(cfg), CompatiblePrefix: "1.", PinnedVersion: HTTPXPinnedVersion, Required: true},
		{Name: "katana", DisplayName: "Katana", Executable: cfg.Tools.Katana, ExecutableEnv: "KATANA_EXECUTABLE", VersionArgs: providerVersionArgs(cfg), CompatiblePrefix: "1.", PinnedVersion: KatanaPinnedVersion, Required: true},
		{Name: "gau", DisplayName: "GAU", Executable: cfg.Tools.GAU, ExecutableEnv: "GAU_EXECUTABLE", VersionArgs: []string{"--version"}, CompatiblePrefix: "2.", PinnedVersion: GAUPinnedVersion, Required: true},
		{Name: "nuclei", DisplayName: "Nuclei", Executable: cfg.Tools.Nuclei, ExecutableEnv: "NUCLEI_EXECUTABLE", VersionArgs: []string{"-version"}, CompatiblePrefix: "3.", PinnedVersion: NucleiPinnedVersion, Required: true},
	}
}

func providerVersionArgs(cfg config.Config) []string {
	return providerUpdateArgs([]string{"-version"}, cfg.Recon.ProviderUpdate)
}

func providerSpecsByName(cfg config.Config) map[string]providercheck.Spec {
	out := make(map[string]providercheck.Spec)
	for _, spec := range ExternalProviderSpecs(cfg) {
		out[spec.Name] = spec
	}
	return out
}
