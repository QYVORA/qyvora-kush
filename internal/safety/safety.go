// Package safety implements the architectural safety model of kush.
//
// Every operation carries metadata describing its class, risk, authorization
// requirement, whether it changes remote state, and whether it is reversible.
// Cloud assessments are read-only and offline by default: snapshot and
// simulation analysis need no authorization and never contact a provider.
// Live provider collection is not implemented and is refused with an honest
// error rather than faked.
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
	// OpSnapshotParse analyzes an offline cloud snapshot. Read-only, no auth.
	OpSnapshotParse = OperationMetadata{
		ID: "kush.snapshot.parse", Name: "cloud snapshot analysis",
		Description: "Parse and analyze an offline cloud snapshot file.",
		Class:       ClassDiscovery, Risk: models.RiskS1, TargetType: "snapshot",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpAnalyze runs the analysis pipeline over collected assets. Read-only.
	OpAnalyze = OperationMetadata{
		ID: "kush.analyze", Name: "cloud configuration analysis",
		Description: "Run IAM, storage, network, container, secret and misconfiguration analysis.",
		Class:       ClassAnalysis, Risk: models.RiskS1, TargetType: "any",
		AuthRequired: false, Confirm: false, ChangesState: false, Reversible: true,
	}
	// OpLiveProvider would contact a real cloud control plane. Not implemented.
	OpLiveProvider = OperationMetadata{
		ID: "kush.live.provider", Name: "live provider collection",
		Description: "Query a live cloud provider API (NOT IMPLEMENTED).",
		Class:       ClassLiveProvider, Risk: models.RiskS2, TargetType: "provider",
		AuthRequired: true, Confirm: true, ChangesState: false, Reversible: true,
	}
)

// Implemented reports whether an operation actually exists in this build.
// Live provider collection is deliberately not implemented; calling it
// must produce an honest error rather than pretend capability.
func (op OperationMetadata) Implemented() bool {
	return op.ID != OpLiveProvider.ID
}

// RequiresAuthorization reports whether an operation only runs on an
// authorized target.
func (op OperationMetadata) RequiresAuthorization() bool { return op.AuthRequired }
