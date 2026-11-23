// Package queryipc provides fixed private worker-to-query HTTP over a Unix socket.
package queryipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/lifecycle"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var ErrUnavailable = errors.New("query_unavailable")

type request struct {
	Filter  query.Filter
	Objects []domain.Object
}
type Client struct{ http *http.Client }

func NewClient(socket string) *Client {
	return &Client{&http.Client{Timeout: 65 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	}, MaxConnsPerHost: 1, DisableKeepAlives: true}}}
}
func (c *Client) Execute(ctx context.Context, f query.Filter, o []domain.Object) ([]domain.QueryRow, error) {
	if e := domain.ValidateObjects(f, o); e != nil {
		return nil, e
	}
	b, e := json.Marshal(request{f, o})
	if e != nil || len(b) > 4<<20 {
		return nil, domain.ErrCapacity
	}
	r, e := http.NewRequestWithContext(ctx, "POST", "http://query/execute", bytes.NewReader(b))
	if e != nil {
		return nil, ErrUnavailable
	}
	v, e := c.http.Do(r)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer v.Body.Close()
	switch v.StatusCode {
	case 413:
		return nil, domain.ErrCapacity
	case 504:
		return nil, domain.ErrQueryTimeout
	case 429:
		return nil, domain.ErrQueryBusy
	}
	if v.StatusCode != 200 {
		return nil, ErrUnavailable
	}
	var rows []domain.QueryRow
	d := json.NewDecoder(io.LimitReader(v.Body, (8<<20)+1))
	d.DisallowUnknownFields()
	if d.Decode(&rows) != nil || len(rows) > domain.MaxQueryRows {
		return nil, ErrUnavailable
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, ErrUnavailable
	}
	return rows, nil
}
func Serve(ctx context.Context, socket string, engine query.Engine) error {
	if !filepath.IsAbs(socket) || filepath.Base(socket) != "query.sock" {
		return domain.ErrInvalid
	}
	if e := os.MkdirAll(filepath.Dir(socket), 0700); e != nil {
		return ErrUnavailable
	}
	if st, e := os.Lstat(socket); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return domain.ErrInvalid
		}
		if e = os.Remove(socket); e != nil {
			return ErrUnavailable
		}
	}
	l, e := net.Listen("unix", socket)
	if e != nil {
		return ErrUnavailable
	}
	defer l.Close()
	defer os.Remove(socket)
	if e = os.Chmod(socket, 0600); e != nil {
		return ErrUnavailable
	}
	if state := lifecycle.FromContext(ctx); state != nil {
		state.SetReady(lifecycle.Query, true)
		defer state.SetReady(lifecycle.Query, false)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state := lifecycle.FromContext(ctx); state != nil && !state.Accepts(lifecycle.Query) {
			http.Error(w, "service_unavailable", 503)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/execute" {
			http.Error(w, "not_found", 404)
			return
		}
		defer r.Body.Close()
		var in request
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil {
			http.Error(w, "invalid_request", 400)
			return
		}
		var extra any
		if d.Decode(&extra) != io.EOF || domain.ValidateObjects(in.Filter, in.Objects) != nil {
			http.Error(w, "invalid_request", 400)
			return
		}
		rows, e := engine.Execute(r.Context(), in.Filter, in.Objects)
		if e != nil {
			status := 422
			code := "query_failed"
			switch {
			case errors.Is(e, domain.ErrCapacity):
				status = 413
				code = "capacity"
			case errors.Is(e, domain.ErrQueryTimeout):
				status = 504
				code = "timeout"
			case errors.Is(e, domain.ErrQueryBusy):
				status = 429
				code = "busy"
			}
			http.Error(w, code, status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 1024, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	e = server.Serve(l)
	close(done)
	if errors.Is(e, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return ErrUnavailable
}
