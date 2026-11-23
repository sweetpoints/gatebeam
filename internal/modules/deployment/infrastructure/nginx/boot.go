package nginx

import (
	"context"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/safety"
	"maps"
	"slices"
	"time"
)

// BootPolicy reuses the online compiler's material, CRL, OCSP and network
// validation. A failed dependency removes the affected site, never its checks.
type BootPolicy struct{}

func targetsFor(sites []app.Site, targets []app.Target) []app.Target {
	used := map[string]bool{}
	for _, site := range sites {
		used[site.Config.DefaultTarget.ID] = true
		for _, route := range site.Config.Routes {
			used[route.Target.ID] = true
		}
	}
	var out []app.Target
	for _, target := range targets {
		if used[target.ID] {
			out = append(out, target)
		}
	}
	return out
}

func (BootPolicy) Prepare(ctx context.Context, b edge.BootBundle, now time.Time) (edge.BootBundle, error) {
	if err := ctx.Err(); err != nil {
		return edge.BootBundle{}, err
	}
	if b.Manifest.Validate() != nil || b.CurrentFloor.Validate() != nil || b.CurrentFloor.Node != b.Manifest.Node || b.VerifiedAt.IsZero() || now.Before(b.VerifiedAt) || now.Before(b.CurrentFloor.RecordedAt) || now.Before(b.Manifest.CreatedAt) {
		return edge.BootBundle{}, domain.ErrUnavailable
	}
	if b.Manifest.Version != b.Plan.Snapshot.Version+"/"+b.Plan.Runtime.Generation || b.Manifest.Generation != b.Plan.Runtime.Generation {
		return edge.BootBundle{}, domain.ErrInvalid
	}
	source := b.Plan
	if b.SourcePlan != nil {
		source = *b.SourcePlan
		if source.Snapshot.Version != b.Plan.Snapshot.Version {
			return edge.BootBundle{}, domain.ErrInvalid
		}
	}
	if b.CurrentFloor.AuthorizationID != "" && b.CurrentFloor.AuthorizationID != source.Snapshot.Version {
		return edge.BootBundle{}, domain.ErrUnavailable
	}
	snapshot := source.Snapshot
	runtime := source.Runtime
	runtime.Now = now
	runtime.Materials = maps.Clone(runtime.Materials)
	bindings := safety.Bindings(runtime)
	if want := b.CurrentFloor.SecurityBindings["management"]; want != "" && want != bindings["management"] {
		runtime.Management = nil
	}
	if want := b.CurrentFloor.SecurityBindings["cloudflare"]; want != "" && want != bindings["cloudflare"] {
		runtime.Cloudflare = edge.CloudflareSet{}
	}
	for id, material := range runtime.Materials {
		if want := b.CurrentFloor.SecurityBindings["material/"+id]; want != "" && want != bindings["material/"+id] {
			delete(runtime.Materials, id)
			continue
		}
		if slices.Contains(b.CurrentFloor.RevokedMaterialIDs, material.VersionID) || slices.Contains(b.CurrentFloor.RevokedMaterialIDs, id) {
			delete(runtime.Materials, id)
		}
	}
	compiler := Compiler{}
	// A management certificate failure must not prevent unrelated sites booting.
	if _, err := compiler.Compile(app.Snapshot{Version: snapshot.Version}, runtime); err != nil {
		runtime.Management = nil
		if _, err := compiler.Compile(app.Snapshot{Version: snapshot.Version}, runtime); err != nil {
			return edge.BootBundle{}, err
		}
	}
	var sites []app.Site
	for _, site := range snapshot.Sites {
		if err := ctx.Err(); err != nil {
			return edge.BootBundle{}, err
		}
		if !site.Config.Enabled {
			continue
		}
		candidate := snapshot
		candidate.Sites = []app.Site{site}
		candidate.Targets = targetsFor(candidate.Sites, snapshot.Targets)
		if _, err := compiler.Compile(candidate, runtime); err == nil {
			sites = append(sites, site)
		}
	}
	snapshot.Sites = sites
	snapshot.Targets = targetsFor(sites, snapshot.Targets)
	artifact, err := compiler.Compile(snapshot, runtime)
	if err != nil {
		return edge.BootBundle{}, err
	}
	if b.SourcePlan != nil || artifact.ID != b.Manifest.ArtifactID {
		b.SourcePlan = &source
		// Offline restriction is distinguishable from the confirmed online generation.
		runtime.Generation = "offline-" + artifact.ID[:32]
		artifact, err = compiler.Compile(snapshot, runtime)
		if err != nil {
			return edge.BootBundle{}, err
		}
	}
	b.Plan = edge.Plan{Snapshot: snapshot, Runtime: runtime}
	b.Files = artifact.Files
	b.Manifest.ArtifactID = artifact.ID
	b.Manifest.Generation = runtime.Generation
	b.Manifest.Version = snapshot.Version + "/" + runtime.Generation
	b.Manifest.MaterialIDs = nil
	for _, material := range runtime.Materials {
		if material.VersionID != "" && !slices.Contains(b.Manifest.MaterialIDs, material.VersionID) {
			b.Manifest.MaterialIDs = append(b.Manifest.MaterialIDs, material.VersionID)
		}
	}
	slices.Sort(b.Manifest.MaterialIDs)
	return b, nil
}
