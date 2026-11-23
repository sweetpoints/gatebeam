package composition

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/integration/statistics"
	"gatebeam/internal/modules/deployment"
	nodebootstrap "gatebeam/internal/modules/deployment/application/bootstrap"
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	nodeinfra "gatebeam/internal/modules/deployment/infrastructure/bootstrap"
	diskfs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/observability"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/transaction"
	"io"
	"net/netip"
	"os"
)

func input(path string, out any) error {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 || st.Mode().Perm()&0022 != 0 {
		return errors.New("protected operator input required")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) {
		return errors.New("operator input changed")
	}
	d := json.NewDecoder(io.LimitReader(f, 1<<20+1))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return errors.New("invalid operator input")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid operator input")
	}
	return nil
}
func OperatorOperation(ctx context.Context, op, config, request string) (any, error) {
	if op == "validate-node" {
		var n domain.NodeDeployment
		if e := input(request, &n); e != nil {
			return nil, e
		}
		if e := n.Validate(); e != nil {
			return nil, e
		}
		return n.Node, nil
	}
	if op == "provision-node" || op == "verify-storage" {
		var r struct {
			Node        domain.NodeDeployment `json:"node"`
			StorageRoot string                `json:"storage_root"`
		}
		if e := input(request, &r); e != nil {
			return nil, e
		}
		if e := r.Node.Validate(); e != nil {
			return nil, e
		}
		plan, e := nodebootstrap.BuildVolumes(r.Node, r.StorageRoot)
		if e != nil {
			return nil, e
		}
		if op == "verify-storage" {
			e = nodebootstrap.VerifyStorage(ctx, plan, nodeinfra.DockerVolumes{})
		} else {
			e = nodebootstrap.Provision(ctx, plan, nodeinfra.DockerVolumes{})
		}
		return map[string]int{"volumes": len(plan)}, e
	}
	if op == "render-node" {
		var r NodeRenderRequest
		if e := input(request, &r); e != nil {
			return nil, e
		}
		e := RenderNodeConfigs(ctx, r)
		return map[string]bool{"rendered": e == nil}, e
	}
	switch op {
	case "prepare-management", "prepare-role", "inspect-boot", "rewrap-role", "verify-role", "register-node", "activate-nodes", "map-legacy-archives":
	default:
		return nil, errors.New("unknown operator operation")
	}
	if op == "prepare-role" {
		var c bootstrap.Config
		if e := input(config, &c); e != nil {
			return nil, e
		}
		if (c.Environment != "production" && c.Environment != "development") || !bootstrap.SupportedMode(c.Mode) || secrets.ValidateRoleRecipients(c.EncryptionRecipients) != nil {
			return nil, ErrProcessCapability
		}
		return PrepareRoleIdentity(ctx, c)
	}
	c, e := bootstrap.Load(config)
	if e != nil {
		return nil, e
	}
	if op == "prepare-management" {
		if c.Mode != "edge" || c.RuntimeProtocol != 1 {
			return nil, ErrProcessCapability
		}
		a, e := netip.ParseAddrPort(c.ManagementAPIAddress)
		if e != nil {
			return nil, e
		}
		b, e := netip.ParseAddrPort(c.ManagementAPIPeerAddress)
		if e != nil {
			return nil, e
		}
		return nodeinfra.InitializeManagementState(c.ManagementAPIStateFile, a, b)
	}
	if op == "inspect-boot" {
		if c.Mode != "edge" || c.RuntimeProtocol != 1 {
			return nil, ErrProcessCapability
		}
		disk, e := diskfs.New(c.EdgeRoot)
		if e != nil {
			return nil, e
		}
		node := domain.NodeRef{ID: c.NodeID, Epoch: c.NodeEpoch}
		bundle, e := disk.LoadConfirmed(ctx, node)
		if e != nil {
			return nil, e
		}
		return runtime.BootEvidence{Node: node, ArtifactID: bundle.Manifest.ArtifactID, Version: bundle.Manifest.Version, Generation: bundle.Manifest.Generation, VerifiedAt: bundle.VerifiedAt}, nil
	}
	if op == "rewrap-role" || op == "verify-role" {
		return MaintainRoleSecrets(ctx, c, op == "verify-role")
	}
	if c.Mode != "migrate" {
		return nil, errors.New("dedicated operator DB configuration required")
	}
	pool, e := postgres.Open(ctx, c)
	if e != nil {
		return nil, e
	}
	defer pool.Close()
	tx := postgres.NewRunner(pool)
	owner := deployment.NewNodes()
	switch op {
	case "register-node":
		var r nodes.NodeRegistration
		if e = input(request, &r); e != nil {
			return nil, e
		}
		var ref domain.NodeRef
		e = tx.Within(ctx, func(sc transaction.Scope) error { var e error; ref, e = owner.RegisterWithin(sc, r); return e })
		return ref, e
	case "activate-nodes":
		var requestNodes struct {
			Nodes []domain.NodeDeployment `json:"nodes"`
		}
		if e = input(request, &requestNodes); e != nil {
			return nil, e
		}
		proof, e := activationProbes(ctx, requestNodes.Nodes, nil)
		if e != nil {
			return nil, e
		}
		e = tx.Within(ctx, func(sc transaction.Scope) error { return owner.ActivateVerifiedWithin(sc, proof) })
		return map[string]bool{"activated": e == nil}, e
	case "map-legacy-archives":
		var r struct {
			NodeID  string            `json:"node_id"`
			Objects map[string]string `json:"objects"`
		}
		if e = input(request, &r); e != nil {
			return nil, e
		}
		e = observability.MapLegacyArchives(ctx, pool, r.NodeID, r.Objects, statistics.Nodes{Registry: owner})
		return map[string]bool{"mapped": e == nil}, e
	default:
		return nil, errors.New("unknown operator operation")
	}
}
