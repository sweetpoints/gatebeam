package bootstrap

import (
	"context"
	"errors"
	"gatebeam/internal/modules/deployment/domain"
	"path"
	"regexp"
	"strings"
)

var ErrStorage = errors.New("controlled private node storage unavailable or mismatched")

type Volume struct {
	Name, Class, Path string
	Node              domain.NodeRef
	Bind              bool
}
type StorageFacts struct {
	Directory bool
	UID, Mode uint32
	Device    uint64
}
type VolumeOperations interface {
	Storage(context.Context, string) (StorageFacts, error)
	Volumes(context.Context, string) ([]Volume, error)
	Create(context.Context, Volume) error
}

var classes = []string{"edge-runtime", "edge-logs", "log-spool", "query-socket", "acme-challenges", "management-acme", "nginx-control", "management-control", "background-jobs-control", "log-query-control", "api-capsules", "edge-capsules", "worker-capsules", "backup-spool"}
var volumeName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,100}$`)
var privatePath = regexp.MustCompile(`^/[a-zA-Z0-9._/-]+$`)

func BuildVolumes(n domain.NodeDeployment, root string) ([]Volume, error) {
	if !n.Node.Valid() || !volumeName.MatchString(n.StoragePrefix) || !privatePath.MatchString(root) || root == "/" || path.Clean(root) != root {
		return nil, ErrStorage
	}
	out := make([]Volume, 0, len(classes))
	for _, class := range classes {
		out = append(out, Volume{Name: n.StoragePrefix + "-" + class, Class: class, Path: path.Join(root, class), Node: n.Node, Bind: true})
	}
	return out, nil
}
func same(a, b Volume) bool {
	return a.Name == b.Name && a.Class == b.Class && a.Path == b.Path && a.Node == b.Node && a.Bind && b.Bind
}
func validatePlan(plan []Volume) bool {
	if len(plan) != len(classes) {
		return false
	}
	first := plan[0]
	prefix := strings.TrimSuffix(first.Name, "-"+first.Class)
	n := domain.NodeDeployment{Node: first.Node, StoragePrefix: prefix}
	want, e := BuildVolumes(n, path.Dir(first.Path))
	if e != nil {
		return false
	}
	for i, v := range plan {
		if !same(v, want[i]) {
			return false
		}
	}
	return true
}
func inspectExisting(plan, existing []Volume) (map[string]bool, error) {
	seen := map[string]Volume{}
	for _, v := range existing {
		if _, ok := seen[v.Name]; ok {
			return nil, ErrStorage
		}
		seen[v.Name] = v
	}
	present := map[string]bool{}
	for _, v := range plan {
		if old, ok := seen[v.Name]; ok {
			if !same(v, old) {
				return nil, ErrStorage
			}
			present[v.Name] = true
		}
	}
	return present, nil
}

// Provision inspects every path and existing volume before creating anything.
// It never changes ownership/permissions, deletes data or adopts another node.
func Provision(ctx context.Context, plan []Volume, ops VolumeOperations) error {
	if !validatePlan(plan) || ops == nil {
		return ErrStorage
	}
	present, e := verifyStorage(ctx, plan, ops)
	if e != nil {
		return e
	}
	prefix := strings.TrimSuffix(plan[0].Name, "-"+plan[0].Class)
	for _, v := range plan {
		if !present[v.Name] {
			if e = ops.Create(ctx, v); e != nil {
				return e
			}
		}
	}
	// A concurrent creator may have used different bind options. Docker's create
	// is idempotent by name, so successful command exit alone is insufficient.
	existing, e := ops.Volumes(ctx, prefix)
	if e != nil {
		return e
	}
	present, e = inspectExisting(plan, existing)
	if e != nil || len(present) != len(plan) {
		return ErrStorage
	}
	return nil
}

func verifyStorage(ctx context.Context, plan []Volume, ops VolumeOperations) (map[string]bool, error) {
	if !validatePlan(plan) || ops == nil {
		return nil, ErrStorage
	}
	facts := map[string]StorageFacts{}
	for _, v := range plan {
		f, e := ops.Storage(ctx, v.Path)
		if e != nil {
			return nil, e
		}
		if !f.Directory || f.UID != 101 || f.Mode != 0700 || f.Device == 0 {
			return nil, ErrStorage
		}
		facts[v.Class] = f
	}
	if facts["edge-runtime"].Device == facts["edge-logs"].Device || facts["edge-runtime"].Device == facts["log-spool"].Device {
		return nil, ErrStorage
	}
	prefix := strings.TrimSuffix(plan[0].Name, "-"+plan[0].Class)
	existing, e := ops.Volumes(ctx, prefix)
	if e != nil {
		return nil, e
	}
	present, e := inspectExisting(plan, existing)
	if e != nil {
		return nil, e
	}
	return present, nil
}

// VerifyStorage checks boot prerequisites without creating or changing volumes.
func VerifyStorage(ctx context.Context, plan []Volume, ops VolumeOperations) error {
	present, e := verifyStorage(ctx, plan, ops)
	if e != nil {
		return e
	}
	if len(present) != len(plan) {
		return ErrStorage
	}
	return nil
}
