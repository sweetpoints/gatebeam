package bootstrap

import (
	"context"
	"gatebeam/internal/modules/deployment/domain"
	"testing"
)

type volumeFake struct {
	facts    map[string]StorageFacts
	existing []Volume
	created  []Volume
	badAfter bool
}

func (f *volumeFake) Storage(_ context.Context, path string) (StorageFacts, error) {
	return f.facts[path], nil
}
func (f *volumeFake) Volumes(context.Context, string) ([]Volume, error) { return f.existing, nil }
func (f *volumeFake) Create(_ context.Context, v Volume) error {
	f.created = append(f.created, v)
	if f.badAfter {
		v.Path = "/foreign"
	}
	f.existing = append(f.existing, v)
	return nil
}
func TestVolumeProvisionChecksAllBeforeAnyWrite(t *testing.T) {
	n := domain.NodeDeployment{Node: domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}, StoragePrefix: "gatebeam-a"}
	plan, e := BuildVolumes(n, "/mnt/gatebeam/a")
	if e != nil {
		t.Fatal(e)
	}
	f := &volumeFake{facts: map[string]StorageFacts{}}
	for _, v := range plan {
		dev := uint64(1)
		if v.Class == "edge-logs" || v.Class == "log-spool" {
			dev = 2
		}
		f.facts[v.Path] = StorageFacts{Directory: true, UID: 101, Mode: 0700, Device: dev}
	}
	last := plan[len(plan)-1]
	bad := f.facts[last.Path]
	bad.Mode = 0755
	f.facts[last.Path] = bad
	if e = Provision(context.Background(), plan, f); e == nil || len(f.created) != 0 {
		t.Fatal("unsafe storage caused partial mutation", e, len(f.created))
	}
	bad.Mode = 0700
	f.facts[last.Path] = bad
	logs := f.facts["/mnt/gatebeam/a/edge-logs"]
	logs.Device = 1
	f.facts["/mnt/gatebeam/a/edge-logs"] = logs
	if e = Provision(context.Background(), plan, f); e == nil || len(f.created) != 0 {
		t.Fatal("logs could consume startup filesystem")
	}
	logs.Device = 2
	f.facts["/mnt/gatebeam/a/edge-logs"] = logs
	if e = Provision(context.Background(), plan, f); e != nil || len(f.created) != len(plan) {
		t.Fatal(e, len(f.created))
	}
	if e = Provision(context.Background(), plan, f); e != nil || len(f.created) != len(plan) {
		t.Fatal("provision is not idempotent", e)
	}
	f.existing[0].Node.Epoch = 2
	if e = Provision(context.Background(), plan, f); e == nil {
		t.Fatal("foreign incarnation volume reused")
	}
}
