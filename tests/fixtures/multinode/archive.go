//go:build integration

package multinode

import (
	"context"
	"encoding/json"
	obs "gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/platform/objectstore"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func (b *Business) Query(t testing.TB, source string) obs.Page {
	t.Helper()
	raw := b.Session.Call(t, "POST", "/log-queries", map[string]any{"source": source, "SiteIDs": []string{b.SiteID}, "From": time.Now().Add(-time.Hour), "To": time.Now().Add(time.Minute)}, 202)
	var job struct{ ID string }
	if json.Unmarshal(raw, &job) != nil || job.ID == "" {
		t.Fatal("missing query job")
	}
	end := time.Now().Add(12 * time.Second)
	var lastState, lastCoverage string
	for time.Now().Before(end) {
		raw = b.Session.Call(t, "GET", "/log-queries/"+job.ID, nil, 200)
		var page obs.Page
		if json.Unmarshal(raw, &page) != nil {
			t.Fatal("invalid query response")
		}
		lastState, lastCoverage = page.Job.State, page.Job.Coverage
		if page.Job.State == "succeeded" || page.Job.State == "failed" {
			return page
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatal("owned query did not finish", lastState, lastCoverage)
	return obs.Page{}
}
func (n *Node) WriteRoleFiles(t testing.TB, role string, files map[string][]byte) {
	t.Helper()
	for name, raw := range files {
		if filepath.Base(name) != name {
			t.Fatal("non-own fixture path")
		}
		if e := os.WriteFile(filepath.Join(n.Secrets[role], name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	helper := n.Info.StoragePrefix + "-config-" + role
	Docker(t, "create", "--name", helper, "--network", "none", "-v", n.Info.StoragePrefix+"-"+role+"-secret:/dest", "gatebeam-edge:local")
	for name := range files {
		Docker(t, "cp", filepath.Join(n.Secrets[role], name), helper+":/dest/"+name)
	}
	Docker(t, "rm", helper)
	Docker(t, "run", "--rm", "--network", "none", "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--cap-add", "DAC_OVERRIDE", "-v", n.Info.StoragePrefix+"-"+role+"-secret:/dest", "--entrypoint", "sh", "gatebeam-edge:local", "-ec", "chmod 600 /dest/*; chown -R 101:101 /dest")
}

type Archive struct {
	Lab  *Lab
	Name string
}

func (l *Lab) EnableArchive(t testing.TB) *Archive {
	t.Helper()
	name := l.Run + "-s3"
	image := "rustfs/rustfs@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2"
	Docker(t, "run", "-d", "--name", name, "--label", "gatebeam.fixture.run="+l.Run, "--network", l.Network, "--ip", "10.254.248.60", "--memory", "512m", "--cpus", "1", "--pids-limit", "128", "--tmpfs", "/data:size=256m,mode=1777", "--tmpfs", "/logs:size=16m,mode=1777", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "-e", "RUSTFS_ACCESS_KEY=test-access-key", "-e", "RUSTFS_SECRET_KEY=test-secret-key", "-e", "RUSTFS_CONSOLE_ENABLE=false", "-p", "127.0.0.1::9000", image, "/data")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupBudget(10*time.Second))
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
	})
	for _, n := range l.Nodes {
		Docker(t, "network", "connect", "--alias", "owned-history", n.Info.StoragePrefix+"_query-egress", name)
	}
	endpoint := "http://" + Docker(t, "port", name, "9000/tcp")
	cfg := objectstore.Config{Endpoint: endpoint, Bucket: "owned-multinode-history", Region: "us-east-1", AccessKey: "test-access-key", SecretKey: "test-secret-key"}
	client := objectstore.Client(cfg)
	deadline := time.Now().Add(15 * time.Second)
	created := false
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		_, e := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(cfg.Bucket)})
		cancel()
		if e == nil {
			created = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !created {
		t.Fatal("owned object store readiness")
	}
	for _, n := range l.Nodes {
		writer := cfg
		writer.Endpoint = "http://10.254.248.60:9000"
		reader := cfg
		reader.Endpoint = "http://owned-history:9000"
		wraw, _ := json.Marshal(writer)
		qraw, _ := json.Marshal(reader)
		c := n.Configs["background-jobs"]
		c.ArchiveCredentialsFile = "/run/gatebeam/archive.json"
		n.Configs["background-jobs"] = c
		raw, _ := json.Marshal(c)
		n.WriteRoleFiles(t, "background-jobs", map[string][]byte{"worker.json": raw, "archive.json": wraw})
		n.WriteRoleFiles(t, "log-query", map[string][]byte{"r2.json": qraw})
		n.Compose(t, "up", "-d", "--no-build", "--no-deps", "--force-recreate", "background-jobs", "log-query")
		// Configuring the owned archive is preparation, before injecting a
		// reader/worker failure. Reuse the same finite startup policy as Activate.
		n.wait(t, "background-jobs", "global-jobs", cleanupBudget(10*time.Second))
		n.wait(t, "log-query", "query", cleanupBudget(10*time.Second))
	}
	return &Archive{Lab: l, Name: name}
}
func (a *Archive) WaitBoth(t testing.TB) {
	t.Helper()
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		var nodes int
		e := a.Lab.Pool.QueryRow(t.Context(), `SELECT count(DISTINCT node_id) FROM observability_archive_objects`).Scan(&nodes)
		if e == nil && nodes == 2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("both nodes did not archive real log objects")
}
func (a *Archive) DisconnectReaders(t testing.TB) {
	t.Helper()
	for _, n := range a.Lab.Nodes {
		Docker(t, "network", "disconnect", n.Info.StoragePrefix+"_query-egress", a.Name)
	}
}
