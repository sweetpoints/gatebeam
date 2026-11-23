// Package telegram sends bounded requests to the fixed Telegram HTTPS origin.
package telegram

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"gatebeam/internal/modules/notification/domain"
	"io"
	"net/http"
	"regexp"
	"time"
)

var tokenPattern = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{1,256}$`)
var chatPattern = regexp.MustCompile(`^-?[0-9]{1,24}$`)

type Sender struct{ Client *http.Client }

// Reuse bounded idle connections; a new transport per delivery would retain
// provider connections after each request.
var providerClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 4, MaxIdleConnsPerHost: 2}}

func (s Sender) Send(ctx context.Context, c domain.Channel, secret []byte, message string) error {
	if !tokenPattern.Match(secret) || !chatPattern.MatchString(c.Recipient) || len(message) > 4096 {
		return domain.ErrDelivery
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client := s.Client
	if client == nil {
		client = providerClient
	}
	copy := *client
	copy.Timeout = 10 * time.Second
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	body, _ := json.Marshal(struct {
		ChatID string `json:"chat_id"`
		Text   string `json:"text"`
	}{c.Recipient, message})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+string(secret)+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return domain.ErrDelivery
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := copy.Do(request)
	if err != nil {
		return domain.ErrDelivery
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return domain.ErrDelivery
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result) != nil || !result.OK {
		return domain.ErrDelivery
	}
	return nil
}
