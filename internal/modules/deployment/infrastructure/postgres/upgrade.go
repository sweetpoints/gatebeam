package postgres

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/postgres/dbgen"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
)

// UpgradeStore is used only by the separate controlled deployment identity.
// Runtime role grants cannot write the journal. There is no expiry takeover.
type UpgradeStore struct{ Pool *pgxpool.Pool }

func (s UpgradeStore) Create(ctx context.Context, r upgrade.Run) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	q := dbgen.New(tx)
	if e = nodeGuard(ctx, q); e != nil {
		return e
	}
	if len(r.Plan.Inventory.Nodes) > 0 {
		if e = checkUpgradeMembers(ctx, q, r.Plan.Inventory.Nodes); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO deployment_upgrade_runs(id,revision,owner_instance,state,document) VALUES($1,$2,$3,$4,$5)`, r.Plan.ID, r.Revision, r.Owner, r.State, b)
	if e != nil {
		return upgrade.ErrConflict
	}
	return tx.Commit(ctx)
}

func (s UpgradeStore) CheckMembers(ctx context.Context, inventory []domain.NodeDeployment) error {
	return checkUpgradeMembers(ctx, dbgen.New(s.Pool), inventory)
}

func checkUpgradeMembers(ctx context.Context, q *dbgen.Queries, inventory []domain.NodeDeployment) error {
	rows, err := q.EnabledNodeTargets(ctx)
	if err != nil {
		return err
	}
	if len(rows) != len(inventory) {
		return upgrade.ErrConflict
	}
	expected := make(map[domain.NodeRef]bool, len(inventory))
	for _, node := range inventory {
		expected[node.Node] = true
	}
	for _, row := range rows {
		ref := domain.NodeRef{ID: uuid.UUID(row.ID.Bytes).String(), Epoch: uint64(row.Epoch)}
		if row.State != "active" || !expected[ref] {
			return upgrade.ErrConflict
		}
	}
	return nil
}
func (s UpgradeStore) Load(ctx context.Context, id string) (upgrade.Run, error) {
	var r upgrade.Run
	var b []byte
	var rev uint64
	var owner, state string
	e := s.Pool.QueryRow(ctx, `SELECT document,revision,owner_instance,state FROM deployment_upgrade_runs WHERE id=$1`, id).Scan(&b, &rev, &owner, &state)
	if e != nil || json.Unmarshal(b, &r) != nil || r.Revision != rev || r.Owner != owner || r.State != state {
		return r, upgrade.ErrConflict
	}
	return r, nil
}
func (s UpgradeStore) Save(ctx context.Context, r upgrade.Run, previous uint64) error {
	if r.Revision != previous+1 {
		return upgrade.ErrConflict
	}
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	tag, e := s.Pool.Exec(ctx, `UPDATE deployment_upgrade_runs SET revision=$1,owner_instance=$2,state=$3,document=$4,updated_at=clock_timestamp() WHERE id=$5 AND revision=$6 AND state IN('running','paused')`, r.Revision, r.Owner, r.State, b, r.Plan.ID, previous)
	if e != nil || tag.RowsAffected() != 1 {
		return upgrade.ErrConflict
	}
	return nil
}

// ApproveUpgradeImages binds a protected registry image-policy update to the
// exact persisted in-flight step. An ordinary same-epoch registration stays immutable.
func (s UpgradeStore) ApproveUpgradeImages(ctx context.Context, step upgrade.Step) error {
	if (len(step.ID) != 40 && len(step.ID) != 41) || step.Kind != "approve-images" || len(step.Images) == 0 {
		return upgrade.ErrInvalid
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	q := dbgen.New(tx)
	if e = nodeManager(ctx, q); e != nil {
		return e
	}
	var raw []byte
	var state string
	if e = tx.QueryRow(ctx, `SELECT document,state FROM deployment_upgrade_runs WHERE id=$1 FOR UPDATE`, step.ID[:36]).Scan(&raw, &state); e != nil {
		return upgrade.ErrConflict
	}
	var run upgrade.Run
	if json.Unmarshal(raw, &run) != nil || state != "running" || run.Pending == nil {
		return upgrade.ErrConflict
	}
	a, _ := json.Marshal(*run.Pending)
	b, _ := json.Marshal(step)
	if !jsonSame(a, b) || step.Kind != "approve-images" {
		return upgrade.ErrConflict
	}
	var registration []byte
	var epoch uint64
	if e = tx.QueryRow(ctx, `SELECT registration,epoch FROM deployment_nodes WHERE id=$1 AND state='active' AND enabled FOR UPDATE`, step.Node.ID).Scan(&registration, &epoch); e != nil || epoch != step.Node.Epoch {
		return upgrade.ErrConflict
	}
	var reg map[string]any
	if json.Unmarshal(registration, &reg) != nil {
		return upgrade.ErrInvalid
	}
	images, ok := reg["BridgeImages"].(map[string]any)
	if !ok {
		return upgrade.ErrInvalid
	}
	var prior map[string]domain.RoleDeployment
	for _, n := range step.Targets {
		if n.Node == step.Node {
			prior = n.Roles
		}
	}
	if prior == nil {
		return upgrade.ErrInvalid
	}
	for role, image := range step.Images {
		expected, ok := prior[role]
		if !ok || !strings.Contains(expected.Image, "@sha256:") || images[role] != expected.Image[strings.LastIndex(expected.Image, "@")+1:] {
			return upgrade.ErrConflict
		}
		if !strings.Contains(image, "@sha256:") {
			return upgrade.ErrInvalid
		}
		images[role] = image[strings.LastIndex(image, "@")+1:]
	}
	registration, e = json.Marshal(reg)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE deployment_nodes SET registration=$1 WHERE id=$2 AND epoch=$3`, registration, step.Node.ID, epoch); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s UpgradeStore) VerifyUpgradeImages(ctx context.Context, step upgrade.Step) error {
	if (len(step.ID) != 40 && len(step.ID) != 41) || step.Kind != "approve-images" {
		return upgrade.ErrInvalid
	}
	var raw, registration []byte
	var state string
	var epoch uint64
	if e := s.Pool.QueryRow(ctx, `SELECT document,state FROM deployment_upgrade_runs WHERE id=$1`, step.ID[:36]).Scan(&raw, &state); e != nil {
		return upgrade.ErrConflict
	}
	var run upgrade.Run
	if json.Unmarshal(raw, &run) != nil || state != "running" && state != "paused" || run.Pending == nil {
		return upgrade.ErrConflict
	}
	expected, _ := json.Marshal(*run.Pending)
	actual, _ := json.Marshal(step)
	if !jsonSame(expected, actual) {
		return upgrade.ErrConflict
	}
	if e := s.Pool.QueryRow(ctx, `SELECT registration,epoch FROM deployment_nodes WHERE id=$1 AND state='active' AND enabled`, step.Node.ID).Scan(&registration, &epoch); e != nil || epoch != step.Node.Epoch {
		return upgrade.ErrConflict
	}
	var reg struct{ BridgeImages map[string]string }
	if json.Unmarshal(registration, &reg) != nil {
		return upgrade.ErrInvalid
	}
	for role, image := range step.Images {
		if reg.BridgeImages[role] != image[strings.LastIndex(image, "@")+1:] {
			return upgrade.ErrConflict
		}
	}
	return nil
}

// RetireNode closes the membership only for the persisted final retirement
// step. The executor completes management exclusion, LB removal and drain first.
func (s UpgradeStore) RetireNode(ctx context.Context, step upgrade.Step) error {
	if len(step.ID) != 40 || step.Kind != "retire-membership" || len(step.Targets) < 2 {
		return upgrade.ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbgen.New(tx)
	if err := nodeManager(ctx, q); err != nil {
		return err
	}
	var raw []byte
	var state string
	if err := tx.QueryRow(ctx, `SELECT document,state FROM deployment_upgrade_runs WHERE id=$1 FOR UPDATE`, step.ID[:36]).Scan(&raw, &state); err != nil {
		return upgrade.ErrConflict
	}
	var run upgrade.Run
	if state != "running" || json.Unmarshal(raw, &run) != nil ||
		run.Plan.Scope != "retire" || run.Plan.Request.Target == nil || *run.Plan.Request.Target != step.Node ||
		run.Pending == nil || run.Next != len(run.Plan.Steps)-1 {
		return upgrade.ErrConflict
	}
	want, _ := json.Marshal(run.Pending)
	proposed, _ := json.Marshal(step)
	if !jsonSame(want, proposed) {
		return upgrade.ErrConflict
	}
	if err := checkUpgradeMembers(ctx, q, step.Targets); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE deployment_nodes SET state='revoked',enabled=false WHERE id=$1 AND epoch=$2 AND enabled AND state='active'`, step.Node.ID, step.Node.Epoch)
	if err != nil || tag.RowsAffected() != 1 {
		return upgrade.ErrConflict
	}
	return tx.Commit(ctx)
}

func (s UpgradeStore) VerifyRetiredNode(ctx context.Context, step upgrade.Step) error {
	q := dbgen.New(s.Pool)
	row, err := q.RegisteredNode(ctx, id(step.Node.ID))
	if err != nil || row.Epoch != int64(step.Node.Epoch) || row.State != "revoked" || row.Enabled {
		return upgrade.ErrConflict
	}
	survivors := make([]domain.NodeDeployment, 0, len(step.Targets))
	for _, node := range step.Targets {
		if node.Node != step.Node {
			survivors = append(survivors, node)
		}
	}
	return checkUpgradeMembers(ctx, q, survivors)
}
