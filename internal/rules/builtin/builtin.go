// Package builtin registers the kush rule set. Every rule reads only the
// provided analysis Env — the malware sample document — and produces
// machine-readable findings with attached evidence. Analysis is static-only;
// kush never executes the sample, and any behavioral statements carry their
// sandbox provenance in the evidence chain.
package builtin

import (
	"context"
	"fmt"
	"strings"

	"github.com/QYVORA/qyvora-kush/internal/analysis"
	"github.com/QYVORA/qyvora-kush/internal/events"
	"github.com/QYVORA/qyvora-kush/internal/malware"
	"github.com/QYVORA/qyvora-kush/internal/rules"
	"github.com/QYVORA/qyvora-kush/pkg/models"
)

// All returns the rules implicit in a stock assessment.
func All() []rules.Rule {
	return []rules.Rule{
		&suspiciousImports{},
		&packedBinary{},
		&unsignedBinary{},
		&persistenceMechanism{},
		&c2Beaconing{},
		&encodedLauncher{},
		&embeddedPayload{},
		&userAgentImpersonation{},
		&networkPrivilegeImports{},
		&highConfidenceIOCs{},
		&behaviorAnomalies{},
		&unverifiedDynamic{},
		&injectionPrimitives{},
		&writableExecutableSection{},
	}
}

// metadata assembles a rule Meta with sane defaults for this rule set.
func metadata(id, name, category, description, recommendation string, sev models.Severity) rules.Meta {
	return rules.Meta{
		ID:                id,
		Name:              name,
		Category:          category,
		Description:       description,
		DefaultSeverity:   sev,
		DefaultConfidence: models.ConfidenceObserved,
		Recommendation:    recommendation,
	}
}

// newFinding fills the derived fields of a finding uniformly.
func newFinding(m rules.Meta, env *analysis.Env, objects []string, attrs map[string]string, ev ...models.Evidence) *models.Finding {
	return &models.Finding{
		RuleID:         m.ID,
		Title:          m.Name,
		Category:       m.Category,
		Description:    m.Description,
		Recommendation: m.Recommendation,
		Severity:       m.DefaultSeverity,
		Confidence:     m.DefaultConfidence,
		Status:         models.StatusDetected,
		State:          models.StateObserved,
		Objects:        objects,
		Attributes:     attrs,
		Evidence:       ev,
		Timestamp:      models.Now(),
	}
}

type suspiciousImports struct{}

func (r *suspiciousImports) Meta() rules.Meta {
	return metadata("KSH-001", "Suspicious process-spawning imports", "execution",
		"The sample statically imports process-creation APIs, consistent with "+
			"launching subsidiary tools or injected payloads.",
		"Confirm against the intended application contract; quarantine "+
			"standalone unexpected imports.",
		models.SeverityHigh)
}

func (r *suspiciousImports) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, im := range malware.SuspiciousImports(env.Sample) {
		ev := env.AddEvidence(models.EvidenceObservation, "static", im.Function,
			im.Library, "process-creation import referenced statically")
		sink.Add(newFinding(r.Meta(), env, []string{"import:" + im.Function},
			map[string]string{"library": im.Library, "function": im.Function}, ev))
	}
	return nil
}

type packedBinary struct{}

func (r *packedBinary) Meta() rules.Meta {
	return metadata("KSH-002", "Packed or high-entropy binary", "obfuscation",
		"The sample reports a packer or carries sections with near-maximum "+
			"entropy, which impedes signature-based detection.",
		"Unpack in an isolated repeater if unpacking is required; pivot on "+
			"import/behavior evidence instead of the packed surface.",
		models.SeverityMedium)
}

func (r *packedBinary) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	if !malware.Packed(env.Sample) {
		return nil
	}
	attrs := map[string]string{"packer": env.Sample.Metadata.Packer, "high_entropy_sections": ""}
	high := 0
	for _, sec := range env.Sample.Sections {
		if sec.Entropy > 7.5 {
			high++
		}
	}
	attrs["high_entropy_sections"] = itoa(high)
	attrs["entry_point"] = env.Sample.Metadata.EP
	attrs["overlay_size"] = itoa(env.Sample.Metadata.Overlay)
	ev := env.AddEvidence(models.EvidenceObservation, "static", "metadata",
		env.Sample.Metadata.Packer, "packer or high-entropy sections present")
	if env.Events != nil {
		env.Events.Info(events.StaticAnalyzed, map[string]any{"packed": true, "high_entropy_sections": high})
	}
	sink.Add(newFinding(r.Meta(), env, []string{"sample:" + env.Sample.SampleID}, attrs, ev))
	return nil
}

type unsignedBinary struct{}

func (r *unsignedBinary) Meta() rules.Meta {
	return metadata("KSH-003", "Unsigned binary with no publisher", "authenticode",
		"The sample is not authenticode-signed, so it carries no publisher "+
			"identity the environment can attest.",
		"Verify the sample hash against vendor distribution channels before "+
			"any handling in production environments.",
		models.SeverityMedium)
}

func (r *unsignedBinary) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	if env.Sample.Metadata.Signed || env.Sample.Metadata.Signer != "" {
		return nil
	}
	ev := env.AddEvidence(models.EvidenceObservation, "metadata", "metadata",
		"signature", "no signed publisher identity present")
	sink.Add(newFinding(r.Meta(), env, []string{"sample:" + env.Sample.SampleID},
		map[string]string{"signer": env.Sample.Metadata.Signer, "signed": "false"}, ev))
	return nil
}

type persistenceMechanism struct{}

func (r *persistenceMechanism) Meta() rules.Meta {
	return metadata("KSH-004", "Persistent autostart mechanism", "persistence",
		"Strings or behavior point to registry autostart keys or a payload drop "+
			"under user AppData, which would survive a reboot.",
		"Remove the autostart entry and dropped stub in an isolated clean "+
			"environment during remediation.",
		models.SeverityHigh)
}

func (r *persistenceMechanism) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	found := []string{}
	for _, s := range env.Sample.Strings {
		if s.Kind == "registry" && strings.Contains(strings.ToLower(s.Value), "currentversion\\run") {
			found = append(found, s.Value)
			ev := env.AddEvidence(models.EvidenceArtifact, "strings", "reg-run",
				s.Value, "autostart registry key referenced")
			sink.Add(newFinding(r.Meta(), env, []string{"registry:" + s.Value},
				map[string]string{"registry": s.Value, "source": "strings"}, ev))
		}
	}
	if len(found) == 0 {
		for _, b := range env.Sample.Behavior {
			if b.Action == "registry" {
				ev := env.AddEvidence(models.EvidenceObservation, "behavior", b.ID,
					b.Detail, "registry autostart observed in sandbox")
				sink.Add(newFinding(r.Meta(), env, []string{"behavior:" + b.ID},
					map[string]string{"detail": b.Detail, "source": "behavior"}, ev))
			}
		}
	}
	return nil
}

type c2Beaconing struct{}

func (r *c2Beaconing) Meta() rules.Meta {
	return metadata("KSH-005", "Command-and-control indicators", "command-and-control",
		"The sample carries network indicators for an external command channel, "+
			"enabling beaconing, command dispatch or data staging.",
		"Block the indicators at the network edge and hunt the same values "+
			"across the estate.",
		models.SeverityCritical)
}

func (r *c2Beaconing) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	seen := map[string]bool{}
	for _, n := range malware.C2Indicators(env.Sample) {
		if seen[n.Value] {
			continue
		}
		seen[n.Value] = true
		ev := env.AddEvidence(models.EvidenceObservation, "network", n.Kind,
			n.Value, n.Note)
		sink.Add(newFinding(r.Meta(), env, []string{n.Kind + ":" + n.Value},
			map[string]string{"kind": n.Kind, "value": n.Value, "tls": boolStr(n.TLS)}, ev))
	}
	return nil
}

type encodedLauncher struct{}

func (r *encodedLauncher) Meta() rules.Meta {
	return metadata("KSH-006", "Encoded command launcher", "execution",
		"Strings contain an encoded command invocation pattern commonly used to "+
			"obfuscate foreign post-exploitation tooling.",
		"Decode in an isolated repeater to reveal the target command line and "+
			"raise end-of-chain detections accordingly.",
		models.SeverityHigh)
}

func (r *encodedLauncher) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	if !malware.EncodedCommandExists(env.Sample) {
		return nil
	}
	ev := env.AddEvidence(models.EvidenceObservation, "strings", "encoded-cmd",
		"encoded command pattern", "encoded launcher string present")
	if env.Events != nil {
		env.Events.Info(events.StringsAnalyzed, map[string]any{"encoded_command": true})
	}
	sink.Add(newFinding(r.Meta(), env, []string{"sample:" + env.Sample.SampleID},
		map[string]string{"pattern": "encoded command launcher"}, ev))
	return nil
}

type embeddedPayload struct{}

func (r *embeddedPayload) Meta() rules.Meta {
	return metadata("KSH-007", "Embedded staged payload", "payload",
		"The sample embeds a child archive, script or binary consistent with a "+
			"two-stage load.",
		"Extract and re-hash the embedded artifacts in an isolated repeater and "+
			"treat them as separate indicators.",
		models.SeverityMedium)
}

func (r *embeddedPayload) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, ef := range env.Sample.Embedded {
		if ef.Kind != "payload" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceArtifact, "static", ef.Name,
			ef.Hash, "embedded payload artifact")
		attrs := map[string]string{"name": ef.Name, "kind": ef.Kind}
		if ef.Hash != "" {
			attrs["hash"] = shortHash(ef.Hash)
		}
		sink.Add(newFinding(r.Meta(), env, []string{"embedded:" + ef.Name}, attrs, ev))
	}
	return nil
}

type userAgentImpersonation struct{}

func (r *userAgentImpersonation) Meta() rules.Meta {
	return metadata("KSH-008", "Browser user-agent impersonation", "exfiltration",
		"The sample advertises a generic browser user-agent, a common disguise "+
			"for covert channel traffic that blends with user web traffic.",
		"Baseline allowed user-agents on egress; alert on unexpected browser "+
			"tokens from non-browser processes.",
		models.SeverityMedium)
}

func (r *userAgentImpersonation) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, n := range env.Sample.Network {
		if n.Kind != "user-agent" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceObservation, "network", "ua",
			n.Value, "browser user-agent impersonation")
		sink.Add(newFinding(r.Meta(), env, []string{"network:user-agent"},
			map[string]string{"value": n.Value}, ev))
		break
	}
	return nil
}

type networkPrivilegeImports struct{}

func (r *networkPrivilegeImports) Meta() rules.Meta {
	return metadata("KSH-009", "Socket imports with process access", "execution",
		"Socket library imports coexist with process-creation imports, the classic "+
			"load-and-beacon footprint.",
		"Confirm the network module against the application contract; otherwise "+
			"treat as malicious convergence.",
		models.SeverityMedium)
}

func (r *networkPrivilegeImports) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	hasNet, hasProc := false, false
	for _, im := range env.Sample.Imports {
		switch strings.ToLower(im.Function) {
		case "connect", "internetopenw", "internetopena":
			hasNet = true
		case "createprocessw", "createprocessa", "winexec":
			hasProc = true
		}
	}
	if !hasNet || !hasProc {
		return nil
	}
	ev := env.AddEvidence(models.EvidenceObservation, "static", "imports",
		"process+network", "network and process-creation import convergence")
	sink.Add(newFinding(r.Meta(), env, []string{"sample:" + env.Sample.SampleID},
		map[string]string{"network_imports": "true", "process_imports": "true"}, ev))
	return nil
}

type highConfidenceIOCs struct{}

func (r *highConfidenceIOCs) Meta() rules.Meta {
	return metadata("KSH-010", "Verified high-confidence IOC catalog", "ioc",
		"The analysis surfaced high-confidence IOCs whose values are corroborated "+
			"by the sample's own surfaces (hashes, strings, network or behavior); "+
			"each is directly consumable by detection and response tooling.",
		"Push the verified values into the SIEM/EDR allow-or-alert sets for matching.",
		models.SeverityInformational)
}

func (r *highConfidenceIOCs) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, ioc := range malware.VerifiedIOCs(env.Sample) {
		if !strings.EqualFold(ioc.Confidence, "high") {
			continue
		}
		ev := env.AddEvidence(models.EvidenceObservation, ioc.Source, ioc.ID,
			ioc.Value, ioc.Note+" (verified against sample surfaces)")
		attrs := map[string]string{"type": ioc.Type, "value": ioc.Value,
			"confidence": ioc.Confidence, "source": ioc.Source, "verified": "true"}
		if ioc.Type == "file_hash" {
			attrs["value"] = shortHash(ioc.Value)
		}
		sink.Add(newFinding(r.Meta(), env, []string{"ioc:" + ioc.ID}, attrs, ev))
	}
	return nil
}

type behaviorAnomalies struct{}

func (r *behaviorAnomalies) Meta() rules.Meta {
	return metadata("KSH-011", "Behavioral anomalies from sandbox", "behavior",
		"Sandbox observations include privilege- or persistence-oriented actions "+
			"beyond a benign file contract.",
		"Correlate with endpoint telemetry; hunt the same primitives on other "+
			"hosts before attributing a benign outcome.",
		models.SeverityHigh)
}

func (r *behaviorAnomalies) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, b := range env.Sample.Behavior {
		if b.Action != "privilege" && b.Action != "registry" {
			continue
		}
		ev := env.AddEvidence(models.EvidenceObservation, "behavior", b.ID,
			b.Detail, "behavior observed in "+b.Sandbox)
		attrs := map[string]string{"action": b.Action, "detail": b.Detail,
			"sandbox": b.Sandbox, "observed": boolStr(b.Observed)}
		sink.Add(newFinding(r.Meta(), env, []string{"behavior:" + b.ID}, attrs, ev))
	}
	return nil
}

type unverifiedDynamic struct{}

func (r *unverifiedDynamic) Meta() rules.Meta {
	return metadata("KSH-012", "Dynamic execution on developer host refused", "behavior",
		"kush refuses to execute the sample locally. Behavioral conclusions "+
			"depend entirely on externally collected sandbox observations and are "+
			"not verified on this host.",
		"Re-run inside a strongly isolated sandbox if first-hand dynamic "+
			"confirmation is required; treat local refusal as the honest default.",
		models.SeverityLow)
}

func (r *unverifiedDynamic) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	hasBehavior := len(env.Sample.Behavior) > 0
	if !hasBehavior {
		ev := env.AddEvidence(models.EvidenceObservation, "control", "kush.dynamic",
			"dynamic execution status", malware.DynamicUnavailable)
		sink.Add(newFinding(r.Meta(), env, []string{"control:kush.dynamic"},
			map[string]string{"implemented": "false", "source": "developer host"}, ev))
		return nil
	}
	ev := env.AddEvidence(models.EvidenceObservation, "control", "kush.dynamic",
		"dynamic execution status", malware.DynamicUnavailable+" evidence attributed to external sandbox")
	sink.Add(newFinding(r.Meta(), env, []string{"control:kush.dynamic"},
		map[string]string{"implemented": "false", "behavior_count": itoa(len(env.Sample.Behavior))}, ev))
	return nil
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}

// ---------------------------------------------------------------------------
// Injection primitives and W^X sections

type injectionPrimitives struct{}

func (r *injectionPrimitives) Meta() rules.Meta {
	return metadata("KSH-013", "Process injection primitives", "execution",
		"The sample imports the classic cross-process injection API set "+
			"(remote allocation, process memory write, remote thread or APC "+
			"injection). Copying code into another process is a hallmark of "+
			"banking trojans and post-exploitation agents.",
		"Verify the importing module against the application contract; otherwise "+
			"treat as a high-priority containment signal.",
		models.SeverityHigh)
}

func (r *injectionPrimitives) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, im := range malware.InjectionImports(env.Sample) {
		ev := env.AddEvidence(models.EvidenceObservation, "static", "imports",
			im.Function, "process-injection primitive imported from "+im.Library)
		sink.Add(newFinding(r.Meta(), env, []string{"import:" + strings.ToLower(im.Library) + ":" + im.Function},
			map[string]string{"library": im.Library, "function": im.Function}, ev))
	}
	return nil
}

type writableExecutableSection struct{}

func (r *writableExecutableSection) Meta() rules.Meta {
	return metadata("KSH-014", "Writable-and-executable section", "obfuscation",
		"A section is mapped writable and executable at once, the W^X violation "+
			"that allows an unpacker or loader to write its own payload into "+
			"live code pages.",
		"Correlate the section with a declared packer; if unpacked code persists "+
			"in memory, treat the mapped section as stage-two content.",
		models.SeverityMedium)
}

func (r *writableExecutableSection) Run(_ context.Context, envAny any, sink *rules.Sink) error {
	env := envAny.(*analysis.Env)
	for _, sec := range malware.WritableExecutableSections(env.Sample) {
		ev := env.AddEvidence(models.EvidenceObservation, "static", "section",
			sec.Name, "section flags grant write and execute ("+sec.Flags+")")
		sink.Add(newFinding(r.Meta(), env, []string{"section:" + sec.Name},
			map[string]string{"section": sec.Name, "flags": sec.Flags,
				"entropy": fmt.Sprintf("%.2f", sec.Entropy)}, ev))
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
