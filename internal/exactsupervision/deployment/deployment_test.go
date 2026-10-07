package deployment_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/tobiasGuta/Reconductor/internal/exactactivation"
	s "github.com/tobiasGuta/Reconductor/internal/exactsupervision"
)

const slotPath = "/reconductor.slice/reconductor-exact.slice/reconductor-exact-slot.slice"

const stopTimeoutDropin = "systemd/reconductor-exact-run@.service.d/90-reconductor-exact-stop-timeout.conf"
const stopTimeoutContents = "[Service]\nTimeoutStopFailureMode=kill\n"

var deploymentArtifacts = []string{
	"README.md", "contract.json", "deployment_test.go",
	stopTimeoutDropin, "systemd/reconductor-exact-slot.slice",
	"systemd/reconductor-exact.slice", "systemd/reconductor.slice",
	"tmpfiles.d/reconductor-exact.conf",
}

func readArtifact(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Preserve object uniqueness rather than silently accepting last-key-wins JSON.
// Numbers are not part of this policy-only schema: budgets and numeric IDs are
// deliberately unresolved. This parser is test-local and issues no authority.
func readJSONValue(d *json.Decoder) (any, error) {
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			obj := make(map[string]any)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, fmt.Errorf("non-string object key")
				}
				if _, exists := obj[name]; exists {
					return nil, fmt.Errorf("duplicate key %q", name)
				}
				value, err := readJSONValue(d)
				if err != nil {
					return nil, err
				}
				obj[name] = value
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("unterminated object: %v", err)
			}
			return obj, nil
		case '[':
			array := make([]any, 0)
			for d.More() {
				value, err := readJSONValue(d)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("unterminated array: %v", err)
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter")
		}
	case json.Number:
		return nil, fmt.Errorf("numeric policy value is not frozen")
	default:
		return v, nil
	}
}

func decodeContract(b []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := readJSONValue(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON: %v", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("contract must be an object")
	}
	return obj, nil
}

func contract(t *testing.T) map[string]any {
	t.Helper()
	b := readArtifact(t, "contract.json")
	c, err := decodeContract(b)
	if err != nil {
		t.Fatal(err)
	}
	var canonical bytes.Buffer
	e := json.NewEncoder(&canonical)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, canonical.Bytes()) {
		t.Fatal("contract must use deterministic sorted-key JSON with a final newline")
	}
	return c
}

func at(t *testing.T, c map[string]any, path string) any {
	t.Helper()
	var value any = c
	for _, key := range strings.Split(path, ".") {
		obj, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("%s traverses a non-object", path)
		}
		value, ok = obj[key]
		if !ok {
			t.Fatalf("missing contract field %s", path)
		}
	}
	return value
}

func expect(t *testing.T, c map[string]any, path string, want any) {
	t.Helper()
	gotBytes, err := json.Marshal(at(t, c, path))
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("%s = %s, want %s", path, gotBytes, wantBytes)
	}
}

func expectFields(t *testing.T, c map[string]any, wants map[string]any) {
	t.Helper()
	for path, want := range wants {
		expect(t, c, path, want)
	}
}

func validateArtifactInventory(root fs.FS) error {
	var files []string
	err := fs.WalkDir(root, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact symlink: %s", path)
		}
		if !entry.IsDir() {
			files = append(files, filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	if !reflect.DeepEqual(files, deploymentArtifacts) {
		return fmt.Errorf("unexpected deployment artifacts (service templates/sysusers/backends prohibited): %v", files)
	}
	return nil
}

func TestArtifactScopeAndPolicyOnlyBoundary(t *testing.T) {
	if err := validateArtifactInventory(os.DirFS(".")); err != nil {
		t.Fatal(err)
	}
	c := contract(t)
	expectFields(t, c, map[string]any{
		"schema_version": "1", "kind": "policy_only_unpromoted_deployment_contract", "systemd_baseline": "v259.9",
		"scope.directory": "internal/exactsupervision/deployment", "scope.documentation": "internal/exactsupervision/deployment/README.md",
		"scope.forbidden_modified_paths": []string{"README.md", ".agents/", "agents/", "internal/hypothesis/eval/", "internal/exactsupervision/native/"},
		"scope.runtime_authority":        false, "scope.production_admission_enabled": false,
		"scope.unimplemented":     []string{"production_peer", "worker_integration", "start_backend", "observer_backend", "dbus", "polkit", "runner_promotion"},
		"future_service.withheld": true, "future_service.installable_artifact_present": false,
		"future_service.template":                    "reconductor-exact-run@.service",
		"future_service.exec_start":                  map[string]any{"status": "unresolved_no_reviewed_production_peer", "command": nil},
		"installation.service_template_installation": "withheld", "installation.default_execution_instance": nil,
		"installation.install_only_not_applied_here": true, "installation.proof_status": "disposable_Fedora_proof_pending",
	})
	var keys []string
	for key := range c {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	wantKeys := strings.Fields("account anchor capacity cleanup_helper deployment_integrity descriptors environment failure future_service hardening installation instance kind observation resources schema_version scope selinux systemd_baseline topology start_authority")
	sort.Strings(wantKeys)
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatal("unknown top-level contract fields; action/authority material is not policy", keys)
	}
}

func TestArtifactInventoryRejectsDropinAndServiceRegressions(t *testing.T) {
	base := make(fstest.MapFS)
	for _, path := range deploymentArtifacts {
		base[path] = &fstest.MapFile{Data: readArtifact(t, path)}
	}
	if err := validateArtifactInventory(base); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		move string
		add  string
	}{
		{name: "missing"},
		{name: "wrong-directory", move: "systemd/service.d/90-reconductor-exact-stop-timeout.conf"},
		{name: "wrong-filename", move: "systemd/reconductor-exact-run@.service.d/91-reconductor-exact-stop-timeout.conf"},
		{name: "service-template", add: "systemd/reconductor-exact-run@.service"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutant := make(fstest.MapFS)
			for path, file := range base {
				mutant[path] = file
			}
			if test.add != "" {
				mutant[test.add] = &fstest.MapFile{Data: []byte("[Service]\nExecStart=/bin/true\n")}
			} else {
				delete(mutant, stopTimeoutDropin)
				if test.move != "" {
					mutant[test.move] = base[stopTimeoutDropin]
				}
			}
			if err := validateArtifactInventory(mutant); err == nil {
				t.Fatal("unsafe artifact inventory accepted")
			}
		})
	}
}

// This deliberately small test-local INI reader retains assignments so scalar
// last-value semantics and list reset/append semantics can be checked separately.
type unitPolicy map[string]map[string][]string

func parseUnit(text string) (unitPolicy, error) {
	unit := make(unitPolicy)
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "" {
				return nil, fmt.Errorf("empty section")
			}
			if unit[section] == nil {
				unit[section] = make(map[string][]string)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || section == "" || key == "" || strings.ContainsAny(line, "\\\"'\x00") {
			return nil, fmt.Errorf("unsupported/malformed assignment %q", line)
		}
		unit[section][key] = append(unit[section][key], value)
	}
	return unit, scanner.Err()
}

func scalar(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func validateStopTimeoutDropin(text string) error {
	u, err := parseUnit(text)
	if err != nil {
		return err
	}
	// Exactly one assignment: even a duplicate that ends in kill is not the
	// reviewed owned artifact. No ExecStart or other directive belongs here.
	want := unitPolicy{"Service": {"TimeoutStopFailureMode": {"kill"}}}
	if !reflect.DeepEqual(u, want) {
		return fmt.Errorf("unexpected stop-timeout drop-in: %v", u)
	}
	return nil
}

func TestStopTimeoutDropinRejectsUnsafeAssignments(t *testing.T) {
	b := readArtifact(t, stopTimeoutDropin)
	if !bytes.Equal(b, []byte(stopTimeoutContents)) {
		t.Fatal("owned drop-in must have exactly the reviewed two-line contents")
	}
	if err := validateStopTimeoutDropin(string(b)); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"[Service]\nTimeoutStopFailureMode=abort\n",
		"[Service]\nTimeoutStopFailureMode=\n",
		"[Service]\nTimeoutStopFailureMode=abort\nTimeoutStopFailureMode=kill\n",
		stopTimeoutContents + "TimeoutStopFailureMode=abort\n",
		stopTimeoutContents + "TimeoutStopFailureMode=kill\n",
		stopTimeoutContents + "ExecStart=/bin/true\n",
		stopTimeoutContents + "KillMode=process\n",
		stopTimeoutContents + "[Unit]\nDescription=unexpected\n",
		"[Unit]\nTimeoutStopFailureMode=kill\n",
	} {
		if err := validateStopTimeoutDropin(text); err == nil {
			t.Fatalf("unsafe owned drop-in accepted: %q", text)
		}
	}
}

func validateEffectiveFailureModes(u unitPolicy) error {
	for _, key := range []string{"TimeoutStartFailureMode", "TimeoutStopFailureMode"} {
		if scalar(u["Service"][key]) != "kill" {
			return fmt.Errorf("effective %s must be kill", key)
		}
	}
	return nil
}

func TestStopTimeoutScalarComposition(t *testing.T) {
	main := "[Service]\nTimeoutStartFailureMode=kill\nTimeoutStopFailureMode=kill\n"
	stock := "[Service]\nTimeoutStopFailureMode=abort\n"
	owned := string(readArtifact(t, stopTimeoutDropin))
	// Explicit synthetic order only: main, service.d/10-timeout-abort.conf,
	// template .d/90-reconductor-exact-stop-timeout.conf, then a later file.
	// This small scalar model does not discover real systemd drop-in precedence;
	// authoritative loaded-property proof still belongs to the fresh Fedora gate.
	for _, test := range []struct {
		name  string
		text  string
		valid bool
	}{
		{"main-unit-alone-insufficient", main + stock, false},
		{"owned-override-restores-kill", main + stock + owned, true},
		{"later-abort-denied", main + stock + owned + stock, false},
		{"later-empty-denied", main + stock + owned + "[Service]\nTimeoutStopFailureMode=\n", false},
		{"start-failure-regression-denied", main + stock + owned + "[Service]\nTimeoutStartFailureMode=abort\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			u, err := parseUnit(test.text)
			if err != nil {
				t.Fatal(err)
			}
			if (validateEffectiveFailureModes(u) == nil) != test.valid {
				t.Fatalf("unexpected effective failure-mode decision: %v", u)
			}
		})
	}
}

func finalEffectiveFailurePolicy() map[string]any {
	return map[string]any{
		"comparison_authority":      "loaded_PID1_configuration_after_all_unit_and_dropin_processing",
		"required_before_admission": true, "main_unit_values_alone_sufficient": false,
		"owned_dropin_presence_alone_sufficient": false, "other_frozen_mechanics_still_required": true,
		"requirements": map[string]any{"TimeoutStartFailureMode": "kill", "TimeoutStopFailureMode": "kill"},
		"mismatch":     "reject_admission",
	}
}

func validateFinalEffectivePolicy(c map[string]any) error {
	integrity, ok := c["deployment_integrity"].(map[string]any)
	if !ok || integrity["verify_loaded_configuration"] != true || integrity["reject_pending_reload_or_mismatch"] != true ||
		!reflect.DeepEqual(integrity["final_effective_properties"], finalEffectiveFailurePolicy()) {
		return fmt.Errorf("final loaded-property integrity requirements changed")
	}
	return nil
}

func TestFinalEffectivePolicyRejectsContractRegressions(t *testing.T) {
	b := readArtifact(t, "contract.json")
	if err := validateFinalEffectivePolicy(contract(t)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"main_unit_values_alone_sufficient", "owned_dropin_presence_alone_sufficient", "required_before_admission", "other_frozen_mechanics_still_required", "verify_loaded_configuration", "reject_pending_reload_or_mismatch"} {
		t.Run(field, func(t *testing.T) {
			c, err := decodeContract(b)
			if err != nil {
				t.Fatal(err)
			}
			policy := c["deployment_integrity"].(map[string]any)
			if field != "verify_loaded_configuration" && field != "reject_pending_reload_or_mismatch" {
				policy = policy["final_effective_properties"].(map[string]any)
			}
			policy[field] = !policy[field].(bool)
			if err := validateFinalEffectivePolicy(c); err == nil {
				t.Fatal("weakened loaded-property contract accepted")
			}
		})
	}
}

func words(values []string) []string {
	result := make([]string, 0)
	for _, value := range values {
		if value == "" {
			result = result[:0]
		} else {
			result = append(result, strings.Fields(value)...)
		}
	}
	return result
}

func validateSlice(unit unitPolicy, slot bool) error {
	allowed := map[string]map[string]bool{
		"Unit":  {"Description": true, "StopWhenUnneeded": true, "RefuseManualStop": true},
		"Slice": {},
	}
	if slot {
		allowed["Install"] = map[string]bool{"WantedBy": true}
	}
	for section, assignments := range unit {
		keys, ok := allowed[section]
		if !ok {
			return fmt.Errorf("unexpected section %s", section)
		}
		for key := range assignments {
			if !keys[key] {
				return fmt.Errorf("unexpected %s.%s", section, key)
			}
		}
	}
	if _, ok := unit["Slice"]; !ok || scalar(unit["Unit"]["Description"]) == "" || scalar(unit["Unit"]["StopWhenUnneeded"]) != "no" || scalar(unit["Unit"]["RefuseManualStop"]) != "yes" {
		return fmt.Errorf("persistent slice settings missing or changed")
	}
	if slot && !reflect.DeepEqual(words(unit["Install"]["WantedBy"]), []string{"multi-user.target"}) {
		return fmt.Errorf("slot must have only the approved boot target")
	}
	return nil
}

func TestExplicitPersistentSlices(t *testing.T) {
	c := contract(t)
	units := []string{"reconductor.slice", "reconductor-exact.slice", s.SlotUnitName}
	parents := []string{"-.slice", units[0], units[1]}
	path := ""
	var topology []map[string]string
	for i, name := range units {
		path += "/" + name
		activation := "parent_dependency"
		if i == len(units)-1 {
			activation = "multi-user.target"
		}
		topology = append(topology, map[string]string{"unit": name, "parent": parents[i], "cgroup": path, "activation": activation})
		unit, err := parseUnit(string(readArtifact(t, "systemd/"+name)))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSlice(unit, i == len(units)-1); err != nil {
			t.Fatal(name, err)
		}
	}
	if path != s.SlotControlGroup {
		t.Fatal("frozen hierarchy changed")
	}
	if path != slotPath {
		t.Fatal("frozen hierarchy changed")
	}
	expectFields(t, c, map[string]any{
		"topology.slices": topology, "topology.slot_unit": s.SlotUnitName, "topology.slot_cgroup": s.SlotControlGroup,
		"topology.execution_cgroup_pattern": slotPath + "/reconductor-exact-run@<32hex>.service",
		"topology.explicit_slices_required": true, "topology.persistent_while_empty": true,
		"topology.stop_when_unneeded": false, "topology.refuse_manual_stop": true, "topology.default_dependencies": true,
		"topology.sentinel_process": false, "topology.activate_execution_at_boot": false,
		"installation.boot_enabled_unit": s.SlotUnitName, "installation.boot_target": "multi-user.target",
		"capacity.model": "serial_one_execution", "capacity.authority": "package_owned_exactsupervision_capacity",
		"capacity.queuing": false, "capacity.soft_concurrency_limit": false,
		"capacity.optional_pid1_defense": map[string]any{"property": "ConcurrencyHardMax", "classification": "defense_in_depth_only", "implemented": false, "replaces_capacity": false},
	})
}

func TestSemanticParserRejectsUnsafeEffectivePolicy(t *testing.T) {
	base := "[Unit]\nDescription=slot\nStopWhenUnneeded=no\nRefuseManualStop=yes\n[Slice]\n[Install]\nWantedBy=obsolete.target\nWantedBy=\nWantedBy=multi-user.target\n"
	u, err := parseUnit(base)
	if err != nil || validateSlice(u, true) != nil {
		t.Fatal("valid list reset rejected", err)
	}
	for _, extra := range []string{"[Unit]\nStopWhenUnneeded=yes\n", "[Unit]\nDefaultDependencies=no\n", "[Unit]\nRequires=reconductor-exact-run@bad.service\n", "[Slice]\nConcurrencySoftMax=1\n", "[Service]\nExecStart=/bin/true\n", "[Install]\nWantedBy=another.target\n"} {
		u, err := parseUnit(base + extra)
		if err == nil && validateSlice(u, true) == nil {
			t.Fatalf("unsafe effective policy accepted: %s", extra)
		}
	}
	for _, text := range []string{"Key=value", "[Unit]\ninvalid", "[Unit]\nKey=quoted\\value", "[]\n"} {
		if _, err := parseUnit(text); err == nil {
			t.Fatalf("malformed policy accepted: %q", text)
		}
	}
}

func TestInstanceGrammarAndFutureServicePolicy(t *testing.T) {
	c := contract(t)
	expectFields(t, c, map[string]any{
		"instance.grammar": "^[0-9a-f]{32}$", "instance.encoding": "lowercase_ascii_hex",
		"instance.all_zero_syntactically_valid": true, "instance.validate_before": "StartUnit", "instance.validator": "exactsupervision.ParseInstanceID",
		"instance.lifecycle_identity_only": true, "instance.arbitrary_escaped_names": false, "instance.reuse_for_recovery": false,
		"future_service.action_input_channels_forbidden": []string{"argv", "environment", "unit_properties", "instance_name", "temporary_file_path"},
		"future_service.handoff":                         map[string]any{"direction": "outbound_empty_handed_peer", "admitted_material_owner": "trusted_worker_broker", "attempt": "one_designated_connection", "reconnect_replay": false, "sandbox_control_socket_access": false},
	})
	r := regexp.MustCompile(at(t, c, "instance.grammar").(string))
	for _, value := range []string{strings.Repeat("0", 32), strings.Repeat("f", 32), strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("a", 31) + "é", strings.Repeat("a", 32) + "\n", strings.Repeat("a", 28) + "\\x2f"} {
		_, err := s.ParseInstanceID(value)
		if r.MatchString(value) != (err == nil) {
			t.Fatalf("manifest grammar disagrees with frozen parser for %q", value)
		}
	}
	p := s.FixedDeploymentPolicy()
	expect(t, c, "future_service.properties", map[string]string{
		"Type": p.Type(), "ExitType": p.ExitType(), "Restart": p.Restart(), "RemainAfterExit": "no", "Delegate": "no", "NotifyAccess": p.NotifyAccess(),
		"Slice": s.SlotUnitName, "User": exactactivation.PeerUser, "Group": exactactivation.PeerGroup, "SupplementaryGroups": "",
		"KillMode": "control-group", "KillSignal": "SIGTERM", "SendSIGKILL": "yes", "FinalKillSignal": "SIGKILL", "OOMPolicy": "kill",
		"TimeoutStartFailureMode": "kill", "TimeoutStopFailureMode": "kill", "RestartForceExitStatus": "",
		"ExecStopPost": "-+/usr/libexec/reconductor/exact-cleanup", "StandardInput": "null", "StandardOutput": "null", "StandardError": "null",
	})
}

func validateTmpfilesPolicy(text string) error {
	var rules [][]string
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			rules = append(rules, strings.Fields(line))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	wantRules := [][]string{{"d", "/run/reconductor-exact", "0755", "root", "root", "-"}, {"f", "/run/reconductor-exact/execution.identity", ":0600", ":" + exactactivation.PeerUser, ":" + exactactivation.PeerGroup, "-"}}
	if !reflect.DeepEqual(rules, wantRules) {
		return fmt.Errorf("unsafe or changed tmpfiles policy: %v", rules)
	}
	return nil
}

func TestCreationOnlyAnchorTmpfilesPolicy(t *testing.T) {
	directory := "d /run/reconductor-exact 0755 root root -\n"
	anchor := "f /run/reconductor-exact/execution.identity :0600 :reconductor-exact :reconductor-exact -\n"
	if err := validateTmpfilesPolicy(directory + anchor); err != nil {
		t.Fatal(err)
	}
	for _, regression := range []string{
		"f /run/reconductor-exact/execution.identity 0600 reconductor-exact reconductor-exact -\n",
		strings.Replace(anchor, ":0600", "0600", 1),
		strings.Replace(anchor, ":reconductor-exact", "reconductor-exact", 1),
		strings.Replace(anchor, ":reconductor-exact -", "reconductor-exact -", 1),
		strings.Replace(anchor, "f ", "f+ ", 1),
		strings.Replace(anchor, ":reconductor-exact", ":991", 1),
		strings.Replace(anchor, ":reconductor-exact -", ":991 -", 1),
		strings.TrimSpace(anchor) + " contents\n",
		strings.Replace(anchor, " -\n", " 1d\n", 1),
	} {
		if err := validateTmpfilesPolicy(directory + regression); err == nil {
			t.Fatalf("unsafe anchor regression accepted: %q", regression)
		}
	}
}

func TestHelperAccountAnchorAndTmpfiles(t *testing.T) {
	c := contract(t)
	if err := validateTmpfilesPolicy(string(readArtifact(t, "tmpfiles.d/reconductor-exact.conf"))); err != nil {
		t.Fatal(err)
	}
	expectFields(t, c, map[string]any{
		"cleanup_helper.path": "/usr/libexec/reconductor/exact-cleanup", "cleanup_helper.arguments": []string{}, "cleanup_helper.wrappers": []string{},
		"cleanup_helper.artifact_requirements":                []string{"reviewed_static_artifact", "root_owned_regular_file", "protected_root_owned_ancestors", "no_group_or_world_write", "no_setuid", "no_setgid", "no_file_capabilities", "no_elf_interpreter_or_dynamic_dependencies", "verified_digest_and_provenance", "expected_selinux_label"},
		"cleanup_helper.static_linkage_sanitizes_environment": false, "cleanup_helper.no_nss_lookup": true,
		"account.provisioning": "trusted_administrator_or_package", "account.sysusers_selected": false,
		"account.user": exactactivation.PeerUser, "account.primary_group": exactactivation.PeerGroup, "account.numeric_uid": nil, "account.numeric_gid": nil,
		"account.requirements":                             []string{"non_root", "stable_static_named_identity", "locked_password", "non_login_shell", "no_useful_home", "no_operator_session", "no_authority_identity_sharing", "no_unrelated_supplementary_memberships"},
		"account.forbidden_memberships":                    []string{"wheel", "docker", "operator"},
		"account.forbidden_authority":                      []string{"generic_cgroup_management", "db_credentials", "redis_credentials", "evidence_credentials", "authority_descriptors"},
		"account.verify_actual_account_and_process_groups": true, "account.supplementary_groups_directive_erases_database_memberships": false,
		"anchor.parent": "/run/reconductor-exact", "anchor.path": "/run/reconductor-exact/execution.identity",
		"anchor.parent_owner": "root:root", "anchor.parent_mode": "0755", "anchor.owner": "reconductor-exact:reconductor-exact", "anchor.mode": "0600",
		"anchor.requirements":      []string{"regular_file", "one_link", "no_setuid", "no_setgid", "no_group_or_world_write", "protected_ancestors", "validated_full_root_runtime_tmpfs"},
		"anchor.contents_semantic": false, "anchor.identity_source": "st_uid_and_st_gid_only", "anchor.provisioning": "tmpfiles_intent_only",
		"anchor.age_cleanup": false, "anchor.automatic_live_replacement": false, "anchor.tmpfiles_is_admission_proof": false,
		"anchor.tmpfiles_attributes": "creation_only", "anchor.tmpfiles_creates_when_absent": true, "anchor.tmpfiles_repairs_existing_mode_or_ownership": false,
		"anchor.admission": map[string]any{"boundary": "future_trusted_start_backend_preflight", "uid_equals_actual_account": true, "gid_equals_actual_primary_group": true, "mismatch_prevents_start": true, "fresh_check_required": true, "privileged_replacement_during_invocation_forbidden": true},
	})
}

func TestAuthorityIntegrityEnvironmentAndDescriptors(t *testing.T) {
	c := contract(t)
	assignments := make(map[string]string)
	for _, assignment := range exactactivation.PeerEnvironment() {
		key, value, _ := strings.Cut(assignment, "=")
		assignments[key] = value
	}
	expectFields(t, c, map[string]any{
		"start_authority.implemented": false, "start_authority.generic_execution_identity_manager_authority": false,
		"start_authority.forbidden_operations":  []string{"generic_systemctl_control", "generic_StartUnit", "generic_KillUnit", "transient_unit_creation", "unit_property_mutation", "arbitrary_manager_dbus"},
		"start_authority.required_before_start": []string{"validate_instance", "verify_deployment_integrity", "verify_account_anchor_binding", "verify_observer_ownership_and_generation", "reserve_serial_capacity", "reference_fixed_instance"},
		"start_authority.operation":             "narrow_fixed_start_only", "start_authority.caller_supplied_properties": false,
		"deployment_integrity.root_owned_reviewed_artifacts": true, "deployment_integrity.verify_digest_and_provenance": true,
		"deployment_integrity.verify_loaded_configuration":       true,
		"deployment_integrity.reject_pending_reload_or_mismatch": true, "deployment_integrity.caller_overrides": false,
		"deployment_integrity.trusted_configuration_stable_until_cleanup": true,
		"environment.peer_assignments":                                    assignments, "environment.shared_helper_environment": "same_fixed_three_trusted_assignments",
		"environment.reset_unit_assignments_before_fixed_values": true, "environment.security_boundary": "complete_trusted_source_closure_before_exec",
		"environment.global_service_environment": "fresh_closed_allowlist_check_before_admission", "environment.unknown_global_entry": "reject_admission",
		"environment.denied_sources":                           []string{"EnvironmentFile", "PassEnvironment", "PAMName", "credentials", "activation", "watchdog", "notification", "LogNamespace", "directory_environment_features", "execution_caller_manager_environment_mutation"},
		"environment.future_fixed_settings":                    map[string]string{"SetLoginEnvironment": "no", "MemoryPressureWatch": "skip", "ExecSearchPath": ""},
		"environment.remove_global_default_path":               true,
		"environment.generated_names_to_remove":                []string{"USER", "INVOCATION_ID", "SYSTEMD_EXEC_PID", "MAINPID", "MAINPIDFDID", "SERVICE_RESULT", "EXIT_CODE", "EXIT_STATUS"},
		"environment.known_name_denylist_is_security_boundary": false, "environment.sanitization_in_main_is_sufficient": false, "environment.checker_implemented": false,
		"descriptors.standard": map[string]string{"stdin": "null", "stdout": "null", "stderr": "null"},
		"descriptors.tty":      false, "descriptors.journal_stream_required": false, "descriptors.authority_bearing_standard_streams": false,
		"descriptors.forbidden_mechanisms": []string{"execution_leaf_socket_activation", "OpenFile", "named_io", "credential_fds", "fd_store_inputs", "watchdog_fd", "notification_fd"},
	})
}

func TestOwnedAndExternalDropinIntegrityContract(t *testing.T) {
	c := contract(t)
	expect(t, c, "deployment_integrity.dropins", map[string]any{
		"applicable_scopes": []string{"type_wide", "template", "instance_specific", "dash_prefix", "alias_related"},
		"search_roots":      []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"},
		"classes": map[string]string{
			"reconductor_owned": "required_exact_reviewed_artifacts", "reviewed_external_vendor": "reviewed_deployment_context_and_provenance", "unknown_unapproved": "reject_admission",
		},
		"owned_artifacts": []map[string]any{{
			"artifact": stopTimeoutDropin, "installed_path": "/usr/lib/systemd/system/reconductor-exact-run@.service.d/90-reconductor-exact-stop-timeout.conf",
			"dormant_without_service_template": true,
			"required_properties":              map[string]string{"TimeoutStopFailureMode": "kill"},
			"requirements":                     []string{"expected_path", "root_owned_protected_ancestors", "root_owned_regular_non_symlink_file", "no_group_or_world_write", "reviewed_content_hash_and_provenance"},
		}},
		"stock_fedora_context": map[string]any{
			"path": "/usr/lib/systemd/system/service.d/10-timeout-abort.conf", "observed_TimeoutStopFailureMode": "abort",
			"type_wide_dropins_affect_exact_services": true, "vendor_file_modification": false, "proof_payload_digest_pinned": false,
		},
		"path_allowlist_alone_is_authority": false, "reject_instance_specific_replacement": true,
		"reject_unexpected_same_name_override": true, "unknown_or_later_effective_mismatch": "reject_admission",
	})
	expect(t, c, "deployment_integrity.final_effective_properties", finalEffectiveFailurePolicy())
}

func TestAPIVFSCorrectionAndHardening(t *testing.T) {
	c := contract(t)
	expect(t, c, "hardening.properties", map[string]string{
		"ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes", "PrivateDevices": "no", "PrivateUsers": "no", "ProtectControlGroups": "yes",
		"ProtectKernelTunables": "no", "ProtectKernelModules": "yes", "ProtectKernelLogs": "no", "ProtectProc": "default", "ProcSubset": "all",
		"PrivateMounts": "yes", "RestrictNamespaces": "no", "CapabilityBoundingSet": "", "AmbientCapabilities": "", "NoNewPrivileges": "yes",
		"RestrictSUIDSGID": "yes", "LockPersonality": "yes", "MemoryDenyWriteExecute": "no", "SystemCallFilter": "",
	})
	expectFields(t, c, map[string]any{
		"hardening.deferred": []string{"PrivateDevices", "ProtectKernelTunables", "ProtectKernelLogs", "MemoryDenyWriteExecute", "SystemCallFilter"},
		"hardening.api_vfs.standalone_mount_apivfs_assignment":         "omitted",
		"hardening.api_vfs.ordinary_setup_implied_by":                  "ProtectControlGroups=yes",
		"hardening.api_vfs.ordinary_cgroup_view":                       "full_host_hierarchy_read_only_no_private_cgroup_namespace",
		"hardening.api_vfs.privileged_stop_post_protection_parameters": "bypassed",
		"hardening.api_vfs.helper_mount_namespace_may_be_cloned":       true, "hardening.api_vfs.require_helper_mount_namespace_equal_pid1": false,
		"hardening.api_vfs.helper_actual_views_required": []string{"/proc", "/sys/fs/cgroup", "/run"},
		"hardening.api_vfs.prohibited_view_replacements": []string{"RootDirectory", "RootImage", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "namespace_joins"},
		"hardening.api_vfs.source_baseline":              "https://github.com/systemd/systemd/tree/v259.9",
	})
}

func TestFinalityCleanupFailureAndUnresolvedResourcePolicy(t *testing.T) {
	c := contract(t)
	confirmation := []string{"original_invocation_final_milestone", "fresh_later_pinned_slot_populated_zero"}
	mechanisms := make([]string, 0)
	for _, mechanism := range s.FixedDeploymentPolicy().ResourceMechanisms() {
		mechanisms = append(mechanisms, string(mechanism))
	}
	expectFields(t, c, map[string]any{
		"capacity.release_requires": confirmation, "observation.cleanup_requires": confirmation,
		"observation.implemented": false, "observation.observer_outside_slot": true, "observation.trusted_evidence_issuer_public": false,
		"observation.original_identity": []string{"boot", "pinned_slot_generation", "owner_generation", "InvocationID"},
		"observation.final_milestone":   map[string]any{"stop_post_observed_and_completed": true, "terminal_states": []map[string]string{{"active": "inactive", "sub": "dead"}, {"active": "failed", "sub": "failed"}}, "control_pid_zero": true, "no_later_invocation_command": true},
		"observation.read_error":        "cleanup_unconfirmed", "observation.child_gc_is_cleanup_proof": false,
		"observation.insufficient":                                []string{"helper_SIGKILL", "helper_write_return", "ExecStopPost_result", "unit_Result", "UnitRemoved", "child_cgroup_disappearance", "early_populated_zero", "cgroup_events_failure"},
		"observation.reference_before_start_until_final_evidence": true, "observation.ordinary_systemd_group_kill_is_atomic_proof": false,
		"failure.helper_failure_or_incomplete_observation": "cleanup_unconfirmed_no_capacity_reuse",
		"failure.automatic_recovery":                       false, "failure.replay": false, "failure.resend": false, "failure.helper_retry": false, "failure.reuse_original_instance": false,
		"failure.quarantine_on":         []string{"unexpected_reactivation", "changed_InvocationID", "lost_observer_identity", "post_final_command"},
		"resources.required_mechanisms": mechanisms, "resources.finite_time_mechanisms": []string{"RuntimeMaxSec", "TimeoutStartSec", "TimeoutStopSec"},
		"resources.numerical_values": nil, "resources.numerical_policy_owner": "4B4B4", "resources.layer": "future_fixed_reviewed_resource_dropin",
		"resources.caller_or_transient_overrides": false, "resources.admission_disabled_until_reviewed_numbers": true,
		"selinux.target": "Fedora_SELinux_Enforcing_stock_policy", "selinux.custom_policy": false, "selinux.enforcement_disable": false,
		"selinux.unconfined_observer_is_production_proof": false, "selinux.future_proof_requires": []string{"inspect_AVCs", "verify_actual_labels", "verify_supported_views_and_operations"},
		"selinux.observer_confinement": "later_deployment_work",
	})
}

func TestContractDecoderRejectsAmbiguityAndNumericPolicy(t *testing.T) {
	for _, raw := range []string{`{"a":false,"a":true}`, `{"nested":{"UID":991}}`, `{"resources":{"MemoryMax":"later","MemoryMax":512}}`, `{} {}`, `[]`, `{"a":`, `{"a":1.5}`} {
		if _, err := decodeContract([]byte(raw)); err == nil {
			t.Fatalf("ambiguous or numeric contract accepted: %s", raw)
		}
	}
}
