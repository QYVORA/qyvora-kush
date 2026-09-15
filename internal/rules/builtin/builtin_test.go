package builtin

import (
	"context"
	"testing"

	"github.com/QYVORA/qyvora-kush/internal/analysis"
	"github.com/QYVORA/qyvora-kush/internal/malware"
	"github.com/QYVORA/qyvora-kush/internal/rules"
)

// benignSample is a clearly-legitimate sample document used to prove the
// FP-prone rules stay silent: no encoded-command token, no injection
// primitives, no W^X sections, no packer, no C2 network presence.
func benignSample() *malware.Sample {
	return &malware.Sample{
		SampleID: "benign",
		Name:     "notepad.exe",
		Source:   malware.SourcePackage,
		Format:   "exe",
		Hashes:   []malware.Hash{{Algorithm: "sha256", Value: "0000"}},
		Metadata: malware.Metadata{Packer: "", Entropy: 6.1, EP: "0x00401000"},
		Sections: []malware.Section{
			{Name: ".text", Virtual: 4096, RawSize: 4096, Entropy: 6.2, Flags: "rx"},
			{Name: ".rdata", Virtual: 1024, RawSize: 1024, Entropy: 5.1, Flags: "r"},
			{Name: ".data", Virtual: 1024, RawSize: 1024, Entropy: 6.9, Flags: "rw"},
		},
		Imports: []malware.Import{
			{Library: "KERNEL32.dll", Function: "WriteFile"},
			{Library: "USER32.dll", Function: "MessageBoxW"},
		},
		Strings: []malware.Str{
			{Value: "-encoding utf8", Kind: "command"},
			{Value: "deploy-encrypt.sh --enable", Kind: "command"},
		},
	}
}

func TestFPRulesStaySilentOnBenignSample(t *testing.T) {
	env := &analysis.Env{Sample: benignSample()}
	underTest := []rules.Rule{
		&suspiciousImports{},
		&packedBinary{},
		&c2Beaconing{},
		&encodedLauncher{},
		&networkPrivilegeImports{},
		&injectionPrimitives{},
		&writableExecutableSection{},
	}
	for _, r := range underTest {
		sink := rules.NewSink()
		if err := r.Run(context.Background(), env, sink); err != nil {
			t.Fatalf("%s: %v", r.Meta().ID, err)
		}
		if sink.Len() != 0 {
			t.Errorf("%s flagged a benign sample: %d findings", r.Meta().ID, sink.Len())
		}
	}
}

func TestInjectionRuleFlagsPrimitives(t *testing.T) {
	env := &analysis.Env{Sample: &malware.Sample{
		Imports: []malware.Import{
			{Library: "KERNEL32.dll", Function: "VirtualAllocEx"},
			{Library: "KERNEL32.dll", Function: "WriteProcessMemory"},
		},
	}}
	sink := rules.NewSink()
	if err := (&injectionPrimitives{}).Run(context.Background(), env, sink); err != nil {
		t.Fatalf("run: %v", err)
	}
	if sink.Len() != 2 {
		t.Fatalf("injection findings = %d, want 2", sink.Len())
	}
}
