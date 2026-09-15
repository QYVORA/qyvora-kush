package analysis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-kush/internal/analysis"
	"github.com/QYVORA/qyvora-kush/internal/events"
	"github.com/QYVORA/qyvora-kush/internal/evidence"
	"github.com/QYVORA/qyvora-kush/internal/malware"
	"github.com/QYVORA/qyvora-kush/internal/pipeline"
	"github.com/QYVORA/qyvora-kush/internal/rules"
	"github.com/QYVORA/qyvora-kush/internal/rules/builtin"
	"github.com/QYVORA/qyvora-kush/pkg/models"
)

// TestSimulationPipelineProducesFindings runs the full analysis pipeline over
// the deterministic simulation and verifies that every known hazard ships a
// finding.
func TestSimulationPipelineProducesFindings(t *testing.T) {
	reg := rules.NewRegistry()
	reg.RegisterAll(builtin.All()...)

	var evBuf bytes.Buffer
	stream := events.NewStream(&evBuf)
	mgr := evidence.New("")
	step := &pipeline.Step{
		Target:   &models.Target{ID: "sim", Type: models.TargetSimulation},
		Sim:      true,
		Events:   stream,
		Evidence: mgr,
		Result: &models.Result{
			ID: "run", Framework: "kush", Target: &models.Target{ID: "sim"}, Sim: true,
		},
	}

	stages := analysis.Stages(reg, map[string]any{}, 1000)
	eng := pipeline.New(stages...)
	if err := eng.Run(context.Background(), step); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	found := map[string]bool{}
	for _, f := range step.Result.Findings {
		found[f.RuleID] = true
	}
	expected := []string{"KSH-001", "KSH-002", "KSH-003", "KSH-004",
		"KSH-005", "KSH-006", "KSH-007", "KSH-008", "KSH-009", "KSH-010",
		"KSH-011", "KSH-012"}
	for _, id := range expected {
		if !found[id] {
			t.Errorf("expected finding %s in simulation", id)
		}
	}
	if mgr.Len() == 0 {
		t.Error("simulation produced no evidence")
	}
	if step.Result.Score <= 0 {
		t.Errorf("expected positive risk score, got %d", step.Result.Score)
	}
	if step.Result.Assets == 0 {
		t.Error("intake found no assets")
	}

	// Event stream must be valid JSONL with the shared envelope.
	for _, line := range bytes.Split(bytes.TrimSpace(evBuf.Bytes()), []byte("\n")) {
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("invalid event line %q: %v", line, err)
		}
		if ev["framework"] != "kush" {
			t.Errorf("event framework = %v", ev["framework"])
		}
	}
}

// TestSamplePipelineAcceptsFileTarget exercises the file-path path with a
// generated sample document.
func TestSamplePipelineAcceptsFileTarget(t *testing.T) {
	reg := rules.NewRegistry()
	reg.RegisterAll(builtin.All()...)

	data, err := malware.Marshal(malware.Simulate(malware.SimulationOptions{}))
	if err != nil {
		t.Fatalf("marshaling sample: %v", err)
	}
	path := writeTemp(t, string(data))

	step := &pipeline.Step{
		Target:   &models.Target{ID: "smp", Type: models.TargetSnapshot, Value: path},
		Events:   events.NewStream(&bytes.Buffer{}),
		Evidence: evidence.New(""),
		Result:   &models.Result{ID: "run", Framework: "kush", Target: &models.Target{ID: "smp"}},
	}
	stages := analysis.Stages(reg, map[string]any{}, 1000)
	if err := pipeline.New(stages...).Run(context.Background(), step); err != nil {
		t.Fatalf("sample run: %v", err)
	}
	var got bool
	for _, f := range step.Result.Findings {
		if f.RuleID == "KSH-005" {
			got = true
		}
	}
	if !got {
		t.Error("expected KSH-005 for c2 indicators in sample")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
