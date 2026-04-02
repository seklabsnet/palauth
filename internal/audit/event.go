package audit

// ActorInfo represents the actor performing an auditable action.
type ActorInfo struct {
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
	IP     string `json:"ip,omitempty"`
}

// TargetInfo represents the target of an auditable action.
type TargetInfo struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Event is the input struct for logging an audit event.
type Event struct {
	EventType  string
	Actor      ActorInfo
	Target     *TargetInfo
	Result     string
	AuthMethod string
	RiskScore  float64
	ProjectID  string
	TraceID    string
	Metadata   map[string]any
}
