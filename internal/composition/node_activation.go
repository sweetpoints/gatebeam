package composition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/operations"
	"gatebeam/internal/platform/lifecycle"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func activationProbes(ctx context.Context, pair []domain.NodeDeployment, client *http.Client) ([]nodes.ActivationProbe, error) {
	if len(pair) != 2 || pair[0].Node.ID == pair[1].Node.ID || pair[0].PrivateAddress != pair[1].PeerAddress || pair[0].PeerAddress != pair[1].PrivateAddress {
		return nil, errors.New("independent two-node cohort required")
	}
	for _, n := range pair {
		if e := n.Validate(); e != nil {
			return nil, e
		}
	}
	if client == nil {
		for _, n := range pair {
			actual, e := (operations.SSHHost{}).Observe(ctx, n)
			if e != nil || !actual.Ready || activationImages(n, actual.Images) != nil {
				return nil, errors.New("actual host image or capability proof unavailable")
			}
		}
		client = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("health redirect denied") }}
	}
	required := map[string][]string{"nginx": {lifecycle.Data}, "management": {lifecycle.Management}, "background-jobs": {lifecycle.GlobalJobs, lifecycle.LocalCleanup}, "internal-ca": {lifecycle.ACME, lifecycle.Status}, "log-query": {lifecycle.Query}}
	out := []nodes.ActivationProbe{}
	for _, n := range pair {
		proof := nodes.ActivationProbe{Node: n.Node, Images: map[string]string{}}
		for _, role := range domain.NodeRoleNames() {
			spec := n.Roles[role]
			proof.Images[role] = strings.Split(spec.Image, "@")[1]
			address := "http://" + net.JoinHostPort(n.PrivateAddress, fmt.Sprint(spec.HealthPort)) + "/status"
			probe, cancel := context.WithTimeout(ctx, 2*time.Second)
			req, e := http.NewRequestWithContext(probe, http.MethodGet, address, nil)
			if e != nil {
				cancel()
				return nil, e
			}
			resp, e := client.Do(req)
			if e != nil {
				cancel()
				return nil, errors.New("node role health unavailable")
			}
			var state lifecycle.Snapshot
			d := json.NewDecoder(io.LimitReader(resp.Body, 32769))
			err := d.Decode(&state)
			end := d.Decode(new(any))
			resp.Body.Close()
			cancel()
			if resp.StatusCode != 200 || err != nil || end != io.EOF || !state.Live || state.Mode != "serving" {
				return nil, errors.New("node role is not serving")
			}
			for _, cap := range required[role] {
				if !state.Ready[cap] {
					return nil, errors.New("node role capability is not ready")
				}
			}
			if role == "nginx" {
				proof.ArtifactID = state.Details["artifact_id"]
				proof.Generation = state.Details["generation"]
			}
		}
		out = append(out, proof)
	}
	return out, nil
}

func activationImages(n domain.NodeDeployment, actual map[string]string) error {
	if len(actual) != len(n.Roles) {
		return errors.New("host roles differ")
	}
	for role, want := range n.Roles {
		if actual[role] != want.Image {
			return errors.New("actual host image differs from authorized inventory")
		}
	}
	return nil
}
