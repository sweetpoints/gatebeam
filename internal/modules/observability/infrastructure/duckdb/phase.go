package duckdb

import "time"

// Only the service's fixed CLI markers survive this writer. Raw DuckDB stderr
// can contain generated SQL and credentials; discard it with bounded storage.
type queryPhases struct {
	started time.Time
	marks   [4]time.Time
	phase   int
	line    [96]byte
	used    int
	dropped bool
}

var queryPhaseNames = [...]string{"configuration", "extension", "settings", "query"}

func (p *queryPhases) Write(raw []byte) (int, error) {
	for _, b := range raw {
		if b == '\n' {
			if !p.dropped && p.phase < len(queryPhaseNames) {
				if string(p.line[:p.used]) == "GATEBEAM_QUERY_PHASE="+queryPhaseNames[p.phase] {
					p.marks[p.phase] = time.Now()
					p.phase++
				}
			}
			clear(p.line[:p.used])
			p.used, p.dropped = 0, false
		} else if p.used < len(p.line) && !p.dropped {
			p.line[p.used] = b
			p.used++
		} else {
			clear(p.line[:p.used])
			p.used, p.dropped = 0, true
		}
	}
	return len(raw), nil
}

func (p *queryPhases) observation(now time.Time) (phase string, phaseMS, cliMS, loadedMS, queryMS int64) {
	phase, last := "startup", p.started
	if p.phase > 0 {
		phase, last = queryPhaseNames[p.phase-1], p.marks[p.phase-1]
		cliMS = p.marks[0].Sub(p.started).Milliseconds()
	}
	if p.phase >= 3 {
		loadedMS = p.marks[2].Sub(p.started).Milliseconds()
	}
	if p.phase == 4 {
		queryMS = p.marks[3].Sub(p.started).Milliseconds()
	}
	return phase, now.Sub(last).Milliseconds(), cliMS, loadedMS, queryMS
}
