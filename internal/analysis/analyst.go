// Package analysis wires the assessment into pipeline stages: sample parse,
// intake, hashing, metadata extraction, static analysis, strings analysis,
// behavior-surface review, network indicators, IOC extraction, threat
// classification and risk calculation. Env is the shared state handed to
// every rule. Analysis never executes the sample on the developer host;
// dynamic execution is not implemented and is refused with an honest error.
package analysis

import (
	"context"

	"github.com/QYVORA/qyvora-kush/internal/errors"
	"github.com/QYVORA/qyvora-kush/internal/events"
	"github.com/QYVORA/qyvora-kush/internal/evidence"
	"github.com/QYVORA/qyvora-kush/internal/malware"
	"github.com/QYVORA/qyvora-kush/internal/pipeline"
	"github.com/QYVORA/qyvora-kush/internal/risk"
	"github.com/QYVORA/qyvora-kush/internal/rules"
	"github.com/QYVORA/qyvora-kush/pkg/models"
)

// Env is the environment passed to every rule during one assessment.
type Env struct {
	Sample *malware.Sample
	Events *events.Stream
	Store  *evidence.Store
	Config map[string]any
}

// AddEvidence records an observation backing a finding, hashed and stored.
func (e *Env) AddEvidence(kind models.EvidenceKind, source, sourceID, target, data string) models.Evidence {
	ev := models.Evidence{
		Kind:     kind,
		Source:   source,
		SourceID: sourceID,
		Target:   target,
		Data:     data,
		State:    models.StateObserved,
	}
	if e.Store != nil {
		e.Store.Add(ev)
	}
	ev.Hash = models.HashContent(ev.Data)
	return ev
}

// Stages returns the full offline/simulation assessment pipeline.
func Stages(reg *rules.Registry, cfg map[string]any, maxEntries int) []pipeline.Stage {
	return []pipeline.Stage{
		{
			ID: "intake", Name: "Sample intake",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.SampleTaken, map[string]any{
						"sample_id": s.SampleID, "name": s.Name, "source": string(s.Source),
						"format": s.Format, "label": s.Label,
					})
				}
				return nil
			},
		},
		{
			ID: "hashing", Name: "Hashing",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				hashes := make(map[string]string, len(s.Hashes))
				for _, h := range s.Hashes {
					hashes[h.Algorithm] = h.Value
				}
				if step.Events != nil {
					step.Events.Info(events.HashCalculated, map[string]any{"hashes": hashes})
				}
				return nil
			},
		},
		{
			ID: "metadata", Name: "Metadata extraction",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				step.Result.Assets = len(s.Embedded)
				if step.Events != nil {
					step.Events.Info(events.MetadataExtracted, map[string]any{
						"assets": step.Result.Assets, "compiler": s.Metadata.Compiler,
						"os": s.Metadata.OS, "arch": s.Metadata.Arch,
						"packer": s.Metadata.Packer, "entropy": s.Metadata.Entropy,
						"packed": malware.Packed(s),
					})
				}
				return nil
			},
		},
		{
			ID: "static", Name: "Static analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				susp := len(malware.SuspiciousImports(s))
				entropy := len(s.Sections)
				if step.Events != nil {
					step.Events.Info(events.StaticAnalyzed, map[string]any{
						"suspicious_imports": susp, "sections": entropy,
						"embedded": len(s.Embedded), "imports": len(s.Imports),
					})
				}
				return nil
			},
		},
		{
			ID: "strings", Name: "Strings analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				notes := len(malware.NotableStrings(s))
				if step.Events != nil {
					step.Events.Info(events.StringsAnalyzed, map[string]any{
						"notable": notes, "total": len(s.Strings),
						"encoded_command": malware.EncodedCommandExists(s),
					})
				}
				return nil
			},
		},
		{
			ID: "behavior", Name: "Behavioral analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.BehaviorAnalyzed, map[string]any{
						"observations": len(s.Behavior), "local_execution": false,
						"verified": len(s.Behavior) == 0,
					})
				}
				return nil
			},
		},
		{
			ID: "network", Name: "Network indicators",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				indicators := malware.C2Indicators(s)
				if step.Events != nil {
					step.Events.Info(events.NetworkIndicators, map[string]any{
						"c2": len(indicators), "total": len(s.Network),
					})
				}
				return nil
			},
		},
		{
			ID: "ioc", Name: "IOC extraction",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.IOCTaken, map[string]any{
						"iocs": len(s.IOCs), "high_confidence": len(malware.HighConfidenceIOCs(s)),
					})
				}
				return nil
			},
		},
		{
			ID: "classify", Name: "Threat classification",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				if step.Events != nil {
					step.Events.Info(events.ThreatClassified, map[string]any{
						"family": s.Threat.Family, "type": s.Threat.Type,
						"severity": s.Threat.Severity, "confidence": s.Threat.Confidence,
					})
				}
				return nil
			},
		},
		{
			ID: "analysis", Name: "Rule analysis",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				if reg == nil {
					return nil
				}
				s, err := currentSample(step)
				if err != nil {
					return err
				}
				env := &Env{
					Sample: s,
					Events: step.Events,
					Store:  step.Evidence,
					Config: cfg,
				}
				sink := rules.NewSink()
				if err := reg.Run(ctx, env, sink); err != nil {
					return err
				}
				for _, f := range sink.List() {
					if step.Target != nil {
						f.TargetID = step.Target.ID
					}
					step.Result.Findings = append(step.Result.Findings, *f)
					if step.Events != nil {
						step.Events.Info(events.FindingDiscovered, map[string]any{
							"rule_id": f.RuleID, "title": f.Title, "severity": string(f.Severity),
							"objects": f.Objects,
						})
					}
				}
				return nil
			},
		},
		{
			ID: "risk", Name: "Risk calculation",
			Run: func(ctx context.Context, step *pipeline.Step) error {
				var assessor risk.Assessor
				score, level := assessor.Assess(ctx, headings(step.Result.Findings))
				step.Result.Score = score
				step.Result.Level = level
				step.Result.Evidence = step.Evidence.List()
				if step.Events != nil {
					step.Events.Info(events.RiskCalculated, map[string]any{
						"score": score, "level": level, "findings": len(step.Result.Findings),
					})
				}
				return nil
			},
		},
	}
}

func headings(fs []models.Finding) []*models.Finding {
	out := make([]*models.Finding, len(fs))
	for i := range fs {
		out[i] = &fs[i]
	}
	return out
}

func currentSample(step *pipeline.Step) (*malware.Sample, error) {
	if step == nil || step.Target == nil {
		return nil, errors.NewExitError(1, "assessment requires a sample or simulation target")
	}
	if step.Sim {
		return malware.Simulate(malware.SimulationOptions{}), nil
	}
	if step.Target.Type != models.TargetSnapshot {
		return nil, errors.NewExitError(1, "unsupported target: dynamic execution and live sandboxing are not implemented; provide a sample document file")
	}
	s, err := malware.LoadFile(step.Target.Value)
	if err != nil {
		return nil, errors.WrapExitError(1, "loading sample", err)
	}
	return s, nil
}
