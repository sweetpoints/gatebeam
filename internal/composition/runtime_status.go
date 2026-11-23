package composition

import (
	"context"
	"encoding/json"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"sync"
	"time"
)

type runtimeRoleStatus struct {
	Role      string              `json:"role"`
	Available bool                `json:"available"`
	Status    *lifecycle.Snapshot `json:"status,omitempty"`
}
type runtimeNodeStatus struct {
	Node  string              `json:"node"`
	Roles []runtimeRoleStatus `json:"roles"`
}
type runtimeOverview struct {
	lifecycle.Snapshot
	Nodes []runtimeNodeStatus `json:"nodes,omitempty"`
}

func readRuntimeOverview(ctx context.Context, cfg bootstrap.Config) runtimeOverview {
	out := runtimeOverview{Snapshot: lifecycle.Snapshot{Live: true, Mode: "legacy", Ready: map[string]bool{lifecycle.Management: true}}}
	if cfg.RuntimeState != nil {
		out.Snapshot = cfg.RuntimeState.Snapshot()
		out.Details = nil
	}
	if len(cfg.HealthEndpoints) > 2 {
		return out
	}
	nodes := []string{}
	for name := range cfg.HealthEndpoints {
		if len(name) > 64 {
			return out
		}
		nodes = append(nodes, name)
	}
	sort.Strings(nodes)
	type destination struct {
		node, role int
		endpoint   string
	}
	var destinations []destination
	roles := []string{"nginx", "management", "background-jobs", "internal-ca", "log-query"}
	for _, node := range nodes {
		current := runtimeNodeStatus{Node: node}
		for _, role := range roles {
			endpoint, ok := cfg.HealthEndpoints[node][role]
			if !ok {
				continue
			}
			index := len(current.Roles)
			current.Roles = append(current.Roles, runtimeRoleStatus{Role: role})
			destinations = append(destinations, destination{len(out.Nodes), index, endpoint})
		}
		out.Nodes = append(out.Nodes, current)
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var wg sync.WaitGroup
	for _, destination := range destinations {
		wg.Go(func() {
			u, e := url.Parse(destination.endpoint)
			if e != nil || u.Scheme != "http" || u.User != nil || u.Path != "/status" || u.RawQuery != "" || u.Fragment != "" {
				return
			}
			ip, e := netip.ParseAddr(u.Hostname())
			if e != nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
				return
			}
			request, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
			if e != nil {
				return
			}
			response, e := client.Do(request)
			if e != nil {
				return
			}
			defer response.Body.Close()
			if response.StatusCode != 200 {
				return
			}
			var status lifecycle.Snapshot
			decoder := json.NewDecoder(io.LimitReader(response.Body, 16385))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&status) != nil {
				return
			}
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				return
			}
			status.Details = nil
			out.Nodes[destination.node].Roles[destination.role].Available = true
			out.Nodes[destination.node].Roles[destination.role].Status = &status
		})
	}
	wg.Wait()
	return out
}
