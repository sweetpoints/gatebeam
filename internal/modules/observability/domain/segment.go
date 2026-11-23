package domain

// Segment.Path is a controlled-volume basename, never an absolute/API path.
type Segment struct {
	NodeID                string
	ID, Path, Fingerprint string
	Offset                int64
	Size                  int64
	Closed                bool
}
type Cursor struct {
	SegmentID   string
	Offset      int64
	Fingerprint string
	Anchor      string
	Dropping    bool
}
type Read struct {
	End                       int64
	Dropping                  bool
	Invalid, Schema, Oversize int64
	Checksum                  string
	Anchor                    string
	Events                    []Event
}
