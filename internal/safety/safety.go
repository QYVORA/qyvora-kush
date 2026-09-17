// Package safety implements the architectural safety model of kush.
//
// Every operation carries metadata describing its class, risk, authorization
// requirement, whether it changes remote state, and whether it is reversible.
// Malware triage is read-only and offline by default: sample-document analysis
// needs no authorization, never executes a sample and never contacts a
// network. Host execution and live dynamic analysis are not implemented and
// are refused with an honest error rather than faked — analysis is static
// only (KSH-012).
package safety

import "github.com/QYVORA/qyvora-kush/pkg/models"

// Class identifies a family of assessment operation.
type Class string

const (
	ClassDiscovery    Class = "discovery"
	ClassAnalysis     Class = "analysis"
	ClassLiveProvider Class = "live-provider"
)

// OperationMetadata describes one operation's safety contract.
type OperationMetadata struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Class        Class            `json:"class"`
	Risk         models.RiskLevel `json:"risk"`
	TargetType   string           `json:"target_type"`
	AuthRequired bool             `json:"authorization_required"`
	Confirm      bool             `json:"confirmation_required"`
	ChangesState bool             `json:"changes_state"`
	Reversible   bool             `json:"reversible"`
}

// Known operations.
var (
	// OpSampleParse triages an offline malware sample document. Read-only,
	// no auth, statically bounded.
	OpSampleParse = OperationMetadata{
		ID: "kush.sample.parse", Name: "sample document triage",
		Description: "Parse a static malware sample document for offline triage.",
		Class:       ClassDiscovery, Risk: models.RiskS1, TargetType: "sample",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpAnalyze runs the static analysis pipeline over a parsed sample.
	// Read-only, bounded to sample files only (never host execution).
	OpAnalyze = OperationMetadata{
		ID: "kush.analyze", Name: "sample static analysis",
		Description: "Run static analysis rules for packers, indicators, behavior and threat classification.",
		Class:       ClassAnalysis, Risk: models.RiskS1, TargetType: "sample",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpHostExecution would run a sample on this host. Not implemented:
	// triage is static only and host execution is refused (KSH-012).
	OpHostExecution = OperationMetadata{
		ID: "kush.host.execution", Name: "host execution of a sample",
		Description: "Execute a sample on the host (NOT IMPLEMENTED — static-only triage; KSH-012 refuses host execution).",
		Class:       ClassLiveProvider, Risk: models.RiskS2, TargetType: "host",
		AuthRequired: true, Confirm: true, ChangesState: true, Reversible: false,
	}
)

// Implemented reports whether an operation actually exists in this build.
// Host execution is deliberately not implemented; calling it must produce an
// honest error rather than pretend capability.
func (op OperationMetadata) Implemented() bool {
	return op.ID != OpHostExecution.ID
}

// RequiresAuthorization reports whether an operation only runs on an
// authorized target.
func (op OperationMetadata) RequiresAuthorization() bool { return op.AuthRequired }
