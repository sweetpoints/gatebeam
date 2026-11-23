package duckdb

import (
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestQueryPhaseObservationIsBoundedOrderedAndDoesNotRetainRawErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &queryPhases{started: time.Now()}
		private := strings.Repeat("private-sql-and-key-", 1000)
		p.Write([]byte(private + "\nGATEBEAM_QUERY_PHASE=query\n"))
		if p.used != 0 || p.phase != 0 {
			t.Fatal("raw errors or an out-of-order marker changed the phase")
		}
		if p.line != [96]byte{} {
			t.Fatal("discarded stderr remained in the bounded buffer")
		}
		time.Sleep(time.Second)
		p.Write([]byte("GATEBEAM_QUERY_PHASE=confi"))
		p.Write([]byte("guration\n"))
		time.Sleep(time.Second)
		p.Write([]byte("GATEBEAM_QUERY_PHASE=extension\n"))
		time.Sleep(2 * time.Second)
		phase, phaseMS, cliMS, loadedMS, queryMS := p.observation(time.Now())
		if phase != "extension" || phaseMS != 2000 || cliMS != 1000 || loadedMS != 0 || queryMS != 0 {
			t.Fatal("extension loading could not be distinguished from CLI startup", phase, phaseMS, cliMS, loadedMS, queryMS)
		}
		p.Write([]byte("GATEBEAM_QUERY_PHASE=settings\n"))
		time.Sleep(time.Second)
		p.Write([]byte("GATEBEAM_QUERY_PHASE=query\nGATEBEAM_QUERY_PHASE=configuration\n"))
		time.Sleep(time.Second)
		phase, phaseMS, cliMS, loadedMS, queryMS = p.observation(time.Now())
		if phase != "query" || phaseMS != 1000 || cliMS != 1000 || loadedMS != 4000 || queryMS != 5000 {
			t.Fatal("actual query timing was changed by an unrelated stderr line", phase, phaseMS, cliMS, loadedMS, queryMS)
		}
	})
}
