package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/postgres/dbgen"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"reflect"
)

func jsonSame(a, b []byte) bool {
	var av, bv any
	return json.Unmarshal(a, &av) == nil && json.Unmarshal(b, &bv) == nil && reflect.DeepEqual(av, bv)
}
func nodeGuard(ctx context.Context, q *dbgen.Queries) error {
	_, err := q.LockNodeRegistry(ctx)
	return err
}
func nodeManager(ctx context.Context, q *dbgen.Queries) error {
	if err := nodeGuard(ctx, q); err != nil {
		return err
	}
	allowed, err := q.CanManageNodes(ctx)
	if err != nil {
		return err
	}
	if !allowed.Valid || !allowed.Bool {
		return nodes.ErrIdentity
	}
	return nil
}
func eligibleNodeLogin(ctx context.Context, tx pgx.Tx, principal string) (bool, error) {
	var eligible bool
	err := tx.QueryRow(ctx, `SELECT rolcanlogin AND NOT EXISTS(
 SELECT 1 FROM pg_roles reachable WHERE (reachable.rolname=$1 OR pg_has_role($1::text,reachable.oid,'SET'))
 AND (reachable.rolsuper OR reachable.rolcreaterole OR reachable.rolcreatedb OR reachable.rolreplication OR reachable.rolbypassrls))
 AND NOT has_table_privilege($1::text,'deployment_nodes'::regclass,'INSERT')
 FROM pg_roles WHERE rolname=$1`, principal).Scan(&eligible)
	return eligible, err
}
func authenticatedNode(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, ref domain.NodeRef) (dbgen.RegisteredNodeRow, error) {
	if err := nodeGuard(ctx, q); err != nil {
		return dbgen.RegisteredNodeRow{}, err
	}
	row, err := q.RegisteredNode(ctx, id(ref.ID))
	if err != nil {
		return row, nodes.ErrIdentity
	}
	principal, err := q.NodeConnectionPrincipal(ctx)
	if err != nil || principal != row.Principal || row.Epoch != int64(ref.Epoch) || row.State != "active" {
		return row, nodes.ErrIdentity
	}
	valid, err := eligibleNodeLogin(ctx, tx, principal)
	if err != nil || !valid {
		return row, nodes.ErrIdentity
	}
	return row, nil
}
func (*Store) AuthenticateNode(sc transaction.Scope, ref domain.NodeRef) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		_, err := authenticatedNode(ctx, tx, dbgen.New(tx), ref)
		return err
	})
}
func (*Store) RegisterNode(sc transaction.Scope, r nodes.NodeRegistration) (out domain.NodeRef, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if err := nodeManager(ctx, q); err != nil {
			return err
		}
		valid, err := eligibleNodeLogin(ctx, tx, r.Principal)
		if err != nil || !valid {
			return nodes.ErrIdentity
		}
		for role, principal := range r.RolePrincipals {
			if role != "background-jobs" || principal == r.Principal {
				return nodes.ErrIdentity
			}
			valid, e := eligibleNodeLogin(ctx, tx, principal)
			if e != nil || !valid {
				return nodes.ErrIdentity
			}
			var duplicate bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deployment_nodes WHERE id<>$1 AND (principal=$2 OR registration->'RolePrincipals'->>'background-jobs'=$2))`, r.Node.ID, principal).Scan(&duplicate); e != nil || duplicate {
				return nodes.ErrIdentity
			}
		}
		var duplicatePrincipal bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deployment_nodes WHERE id<>$1 AND registration->'RolePrincipals'->>'background-jobs'=$2)`, r.Node.ID, r.Principal).Scan(&duplicatePrincipal); e != nil || duplicatePrincipal {
			return nodes.ErrIdentity
		}
		seenRecipients := map[string]bool{}
		for role, recipient := range r.EncryptionRecipients {
			switch role {
			case "api", "provider", "notification", "ca", "leaf":
			default:
				return nodes.ErrIdentity
			}
			if _, e := secrets.NewRecipient(recipient); e != nil || seenRecipients[recipient] {
				return nodes.ErrIdentity
			}
			seenRecipients[recipient] = true
			var duplicate bool
			if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deployment_nodes n,jsonb_each_text(n.registration->'EncryptionRecipients') p WHERE n.id<>$1 AND p.value=$2)`, r.Node.ID, recipient).Scan(&duplicate); e != nil || duplicate {
				return nodes.ErrIdentity
			}
		}
		stored := r
		stored.Original = nil
		body, err := json.Marshal(stored)
		if err != nil {
			return err
		}
		previous, err := q.RegisteredNode(ctx, id(r.Node.ID))
		if err == nil {
			if r.Node.Epoch == uint64(previous.Epoch) {
				if previous.State != "active" || !jsonSame(previous.Registration, body) {
					return domain.ErrConflict
				}
			} else {
				if r.Node.Epoch != uint64(previous.Epoch)+1 {
					return domain.ErrConflict
				}
				var prior nodes.NodeRegistration
				if json.Unmarshal(previous.Registration, &prior) != nil || r.Principal == previous.Principal {
					return nodes.ErrIdentity
				}
				for role, public := range prior.EncryptionRecipients {
					if public != "" && (r.EncryptionRecipients[role] == "" || r.EncryptionRecipients[role] == public) {
						return nodes.ErrIdentity
					}
				}
				for role, principal := range prior.RolePrincipals {
					if principal != "" && (r.RolePrincipals[role] == "" || r.RolePrincipals[role] == principal) {
						return nodes.ErrIdentity
					}
				}
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		} else if r.Node.Epoch != 1 {
			return domain.ErrConflict
		}
		if r.Original != nil {
			original, err := q.LegacyOriginNode(ctx)
			if err == nil && original != r.Node.ID {
				return domain.ErrConflict
			}
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if err = q.RegisterNode(ctx, dbgen.RegisterNodeParams{ID: id(r.Node.ID), Epoch: int64(r.Node.Epoch), Principal: r.Principal, Registration: body, LegacyOrigin: r.Original != nil}); err != nil {
			return err
		}
		if r.Original != nil {
			observation := *r.Original
			legacy, err := q.CurrentVerified(ctx)
			if err != nil {
				return domain.ErrConflict
			}
			if observation.ReleaseID != legacy.ReleaseID || observation.ArtifactID != legacy.ArtifactID || legacy.Version != observation.ReleaseID+"/"+observation.Generation || observation.ImageDigest != r.BridgeImages["nginx"] {
				return domain.ErrConflict
			}
			material, err := q.CurrentMaterialBindings(ctx)
			if err != nil {
				return err
			}
			if err = json.Unmarshal(material.MaterialBindings, &observation.Bindings); err != nil {
				return err
			}
			if err = saveNodeObservation(ctx, q, observation); err != nil {
				return err
			}
		}
		out = r.Node
		return nil
	})
	return
}
func (*Store) ActivateNodes(sc transaction.Scope, refs []domain.NodeRef) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if err := nodeManager(ctx, q); err != nil {
			return err
		}
		legacy, legacyErr := q.CurrentVerified(ctx)
		if legacyErr != nil && !errors.Is(legacyErr, pgx.ErrNoRows) {
			return legacyErr
		}
		var enabled []pgtype.UUID
		for _, ref := range refs {
			row, err := q.RegisteredNode(ctx, id(ref.ID))
			if err != nil || row.Epoch != int64(ref.Epoch) || row.State != "active" {
				return domain.ErrUnavailable
			}
			var registration nodes.NodeRegistration
			if err = json.Unmarshal(row.Registration, &registration); err != nil {
				return err
			}
			if registration.RuntimeProtocol != 1 || registration.BootFormat != 1 || registration.BootArtifactID == "" || len(registration.RoleProtocols) != len(domain.NodeRoleNames()) {
				return domain.ErrUnavailable
			}
			for _, protocol := range registration.RoleProtocols {
				if protocol != 1 {
					return domain.ErrUnavailable
				}
			}
			if legacyErr == nil {
				current, err := q.CurrentNodeRuntime(ctx, dbgen.CurrentNodeRuntimeParams{NodeID: id(ref.ID), NodeEpoch: int64(ref.Epoch)})
				if err != nil || current.ReleaseID != legacy.ReleaseID {
					return domain.ErrUnavailable
				}
				var observation nodes.Observation
				if err = json.Unmarshal(current.Body, &observation); err != nil || observation.State != "succeeded" {
					return domain.ErrUnavailable
				}
			}
			enabled = append(enabled, id(ref.ID))
		}
		return q.EnableNodeMembership(ctx, enabled)
	})
}
func (*Store) SetNodeStatus(sc transaction.Scope, ref domain.NodeRef, state string) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if err := nodeManager(ctx, q); err != nil {
			return err
		}
		previous, err := q.RegisteredNode(ctx, id(ref.ID))
		if err != nil {
			return err
		}
		if state == "active" && previous.State != "active" {
			return domain.ErrConflict
		}
		n, err := q.SetNodeStatus(ctx, dbgen.SetNodeStatusParams{ID: id(ref.ID), Epoch: int64(ref.Epoch), State: state})
		if err != nil {
			return err
		}
		if n != 1 {
			return domain.ErrConflict
		}
		return nil
	})
}
func (*Store) ActiveNodeTargets(sc transaction.Scope) (out []domain.NodeRef, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if err := nodeGuard(ctx, q); err != nil {
			return err
		}
		rows, err := q.EnabledNodeTargets(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, domain.NodeRef{ID: uuid.UUID(row.ID.Bytes).String(), Epoch: uint64(row.Epoch)})
		}
		if len(out) != 0 && len(out) != 2 {
			return domain.ErrUnavailable
		}
		return nil
	})
	return
}
func (*Store) SetNodeDesired(sc transaction.Scope, releaseID string, targets []domain.NodeRef) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if err := nodeGuard(ctx, q); err != nil {
			return err
		}
		if err := q.RetireDesired(ctx); err != nil {
			return err
		}
		for _, ref := range targets {
			if err := q.InsertDesiredNode(ctx, dbgen.InsertDesiredNodeParams{ReleaseID: id(releaseID), NodeID: id(ref.ID), NodeEpoch: int64(ref.Epoch)}); err != nil {
				return err
			}
		}
		return nil
	})
}
func saveNodeObservation(ctx context.Context, q *dbgen.Queries, o nodes.Observation) error {
	if o.Bindings == nil {
		o.Bindings = []release.MaterialBinding{}
	}
	body, err := json.Marshal(o)
	if err != nil {
		return err
	}
	bindings, err := json.Marshal(o.Bindings)
	if err != nil {
		return err
	}
	old, err := q.NodeEvent(ctx, dbgen.NodeEventParams{NodeID: id(o.Node.ID), NodeEpoch: int64(o.Node.Epoch), ReleaseID: id(o.ReleaseID), EventID: id(o.EventID)})
	if err == nil {
		if !jsonSame(old.Body, body) || !jsonSame(old.MaterialBindings, bindings) {
			return domain.ErrConflict
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	latest, err := q.LatestNodeEventTime(ctx, dbgen.LatestNodeEventTimeParams{NodeID: id(o.Node.ID), NodeEpoch: int64(o.Node.Epoch), ReleaseID: id(o.ReleaseID)})
	if err != nil {
		return err
	}
	if latest.Valid && o.ObservedAt.Before(latest.Time) {
		return domain.ErrConflict
	}
	observed := pgtype.Timestamptz{Time: o.ObservedAt, Valid: true}
	if err = q.InsertNodeEvent(ctx, dbgen.InsertNodeEventParams{NodeID: id(o.Node.ID), NodeEpoch: int64(o.Node.Epoch), ReleaseID: id(o.ReleaseID), EventID: id(o.EventID), Body: body, MaterialBindings: bindings, ObservedAt: observed}); err != nil {
		return err
	}
	if o.State == "succeeded" || o.State == "restricted" {
		return q.SaveNodeRuntime(ctx, dbgen.SaveNodeRuntimeParams{NodeID: id(o.Node.ID), NodeEpoch: int64(o.Node.Epoch), ReleaseID: id(o.ReleaseID), Body: body, MaterialBindings: bindings, ObservedAt: observed})
	}
	return nil
}
func (*Store) ReportNode(sc transaction.Scope, o nodes.Observation) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		row, err := authenticatedNode(ctx, tx, q, o.Node)
		if err != nil {
			return err
		}
		var registration nodes.NodeRegistration
		if err = json.Unmarshal(row.Registration, &registration); err != nil {
			return err
		}
		if registration.BridgeImages["nginx"] != o.ImageDigest {
			return nodes.ErrIdentity
		}
		allowed, err := q.NodeReportAllowed(ctx, dbgen.NodeReportAllowedParams{NodeID: id(o.Node.ID), NodeEpoch: int64(o.Node.Epoch), ReleaseID: id(o.ReleaseID)})
		if err != nil || !allowed.Valid || !allowed.Bool {
			return domain.ErrConflict
		}
		return saveNodeObservation(ctx, q, o)
	})
}
func (*Store) ListNodeObservations(sc transaction.Scope, releaseID string) (out []nodes.Observation, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := dbgen.New(tx).NodeReleaseObservations(ctx, id(releaseID))
		if err != nil {
			return err
		}
		out = []nodes.Observation{}
		for _, row := range rows {
			observation := nodes.Observation{Node: domain.NodeRef{ID: uuid.UUID(row.NodeID.Bytes).String(), Epoch: uint64(row.NodeEpoch)}, ReleaseID: releaseID, State: "waiting"}
			if len(row.Body) > 0 {
				if err = json.Unmarshal(row.Body, &observation); err != nil {
					return err
				}
			}
			observation.NodeState = row.NodeState
			out = append(out, observation)
		}
		return nil
	})
	return
}
func (*Store) CurrentNodeObservation(sc transaction.Scope, ref domain.NodeRef) (out nodes.Observation, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if _, err := authenticatedNode(ctx, tx, q, ref); err != nil {
			return err
		}
		row, err := q.CurrentNodeRuntime(ctx, dbgen.CurrentNodeRuntimeParams{NodeID: id(ref.ID), NodeEpoch: int64(ref.Epoch)})
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err = json.Unmarshal(row.Body, &out); err != nil {
			return err
		}
		return json.Unmarshal(row.MaterialBindings, &out.Bindings)
	})
	return
}

// Check compile-time owner contracts and keep private principal data out of REST.
var _ nodes.Repository = (*Store)(nil)

func (*Store) AuthenticateNodeImage(sc transaction.Scope, ref domain.NodeRef, image string) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		row, err := authenticatedNode(ctx, tx, dbgen.New(tx), ref)
		if err != nil {
			return err
		}
		var registration nodes.NodeRegistration
		if err = json.Unmarshal(row.Registration, &registration); err != nil {
			return err
		}
		if registration.BridgeImages["nginx"] != image {
			return nodes.ErrIdentity
		}
		return nil
	})
}
func (*Store) RequireDesiredNode(sc transaction.Scope, ref domain.NodeRef, releaseID string) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if _, err := authenticatedNode(ctx, tx, q, ref); err != nil {
			return err
		}
		desired, err := q.CurrentDesiredNode(ctx, dbgen.CurrentDesiredNodeParams{NodeID: id(ref.ID), NodeEpoch: int64(ref.Epoch)})
		if err != nil || desired != releaseID {
			return domain.ErrConflict
		}
		return nil
	})
}

func (*Store) NodeManagementPrincipal(sc transaction.Scope) (principal string, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if err := nodeManager(ctx, q); err != nil {
			return err
		}
		var err error
		principal, err = q.NodeConnectionPrincipal(ctx)
		return err
	})
	return
}

// NodeRecipientWithin returns operator-registered public material under the
// node-registry lock. Quarantined, revoked and obsolete incarnations fail.
func (*Store) NodeRecipientWithin(sc transaction.Scope, ref domain.NodeRef, role string) (recipient string, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if e := nodeGuard(ctx, q); e != nil {
			return e
		}
		r, e := q.RegisteredNode(ctx, id(ref.ID))
		if e != nil || r.Epoch != int64(ref.Epoch) || r.State != "active" {
			return nodes.ErrIdentity
		}
		var registration nodes.NodeRegistration
		if json.Unmarshal(r.Registration, &registration) != nil {
			return nodes.ErrIdentity
		}
		recipient = registration.EncryptionRecipients[role]
		if recipient == "" {
			return nodes.ErrIdentity
		}
		return nil
	})
	return
}

// ReadRoleRecipientWithin is a read-only readiness snapshot. The locked
// RecipientWithin remains the final certificate-distribution authority.
func (*Store) ReadRoleRecipientWithin(sc transaction.Scope, ref domain.NodeRef, role string) (recipient string, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		r, e := dbgen.New(tx).RegisteredNode(ctx, id(ref.ID))
		if e != nil || r.Epoch != int64(ref.Epoch) || r.State != "active" {
			return nodes.ErrIdentity
		}
		var registration nodes.NodeRegistration
		if json.Unmarshal(r.Registration, &registration) != nil {
			return nodes.ErrIdentity
		}
		recipient = registration.EncryptionRecipients[role]
		if recipient == "" {
			return nodes.ErrIdentity
		}
		return nil
	})
	return
}

func (*Store) AuthorizeLegacyMappingWithin(sc transaction.Scope, node string) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		if e := nodeManager(ctx, dbgen.New(tx)); e != nil {
			return e
		}
		var allowed bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deployment_nodes WHERE id=$1 AND legacy_origin AND state='active')`, node).Scan(&allowed); e != nil {
			return e
		}
		if !allowed {
			return nodes.ErrIdentity
		}
		return nil
	})
}

func (*Store) VerifyNodeActivationWithin(sc transaction.Scope, proof []nodes.ActivationProbe) error {
	return platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		q := dbgen.New(tx)
		if e := nodeManager(ctx, q); e != nil {
			return e
		}
		current, currentErr := q.CurrentVerified(ctx)
		if currentErr != nil && !errors.Is(currentErr, pgx.ErrNoRows) {
			return currentErr
		}
		for _, p := range proof {
			row, e := q.RegisteredNode(ctx, id(p.Node.ID))
			if e != nil || row.Epoch != int64(p.Node.Epoch) || row.State != "active" {
				return nodes.ErrIdentity
			}
			var r nodes.NodeRegistration
			if json.Unmarshal(row.Registration, &r) != nil || r.Node != p.Node {
				return nodes.ErrIdentity
			}
			for role, digest := range p.Images {
				if r.BridgeImages[role] != digest || r.RoleProtocols[role] != 1 {
					return nodes.ErrIdentity
				}
			}
			if errors.Is(currentErr, pgx.ErrNoRows) {
				if p.ArtifactID != r.BootArtifactID {
					return domain.ErrConflict
				}
				continue
			}
			observation, e := q.CurrentNodeRuntime(ctx, dbgen.CurrentNodeRuntimeParams{NodeID: id(p.Node.ID), NodeEpoch: int64(p.Node.Epoch)})
			if e != nil || observation.ReleaseID != current.ReleaseID {
				return domain.ErrUnavailable
			}
			var native nodes.Observation
			if json.Unmarshal(observation.Body, &native) != nil || native.State != "succeeded" || native.Node != p.Node || native.ArtifactID != p.ArtifactID || native.Generation != p.Generation {
				return domain.ErrConflict
			}
		}
		return nil
	})
}

func (*Store) ReadActiveTargetsWithin(sc transaction.Scope) (out []domain.NodeRef, err error) {
	err = platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := dbgen.New(tx).EnabledNodeTargets(ctx)
		if e != nil {
			return e
		}
		for _, r := range rows {
			out = append(out, domain.NodeRef{ID: uuid.UUID(r.ID.Bytes).String(), Epoch: uint64(r.Epoch)})
		}
		if len(out) != 2 {
			return domain.ErrUnavailable
		}
		return nil
	})
	return
}
