package domain

type CapacityLimit struct {
	MemoryBytes int64 `json:"memory_bytes"`
	NanoCPUs    int64 `json:"nano_cpus"`
	PIDs        int64 `json:"pids"`
}
type CapacityTrial struct {
	Node            NodeRef                  `json:"node"`
	MachineType     string                   `json:"machine_type"`
	Images          map[string]string        `json:"images"`
	Limits          map[string]CapacityLimit `json:"limits"`
	DurationSeconds int64                    `json:"duration_seconds"`
	Requests        int64                    `json:"requests"`
	Errors          int64                    `json:"errors"`
	P95Millis       float64                  `json:"p95_millis"`
	Workload        string                   `json:"workload"`
}
type CapacityEvidence struct {
	Kind            string          `json:"kind"`
	RequiredPeakRPS float64         `json:"required_peak_rps"`
	Digest          string          `json:"digest,omitempty"`
	Trials          []CapacityTrial `json:"trials"`
}
