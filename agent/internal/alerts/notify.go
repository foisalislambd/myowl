// Package alerts evaluates alert rules and delivers notifications.
package alerts

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/myowl/myowl/agent/internal/config"
)

// Message is a notification payload.
type Message struct {
	Title    string `json:"title"`
	Text     string `json:"message"`
	Severity string `json:"severity"`
	Host     string `json:"host"`
	TS       int64  `json:"ts"`
}

// Notifier delivers messages to configured channels.
type Notifier struct {
	cfg    *config.Config
	client *http.Client
	Demo   bool
}

// NewNotifier creates a notifier.
func NewNotifier(cfg *config.Config) *Notifier {
	return &Notifier{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}}
}

// Channels lists configured channel names.
func (n *Notifier) Channels() map[string]bool {
	c := n.cfg.Notify
	return map[string]bool{
		"dashboard": true,
		"webhook":   c.Webhook.URL != "" || n.Demo,
		"telegram":  (c.Telegram.BotToken != "" && c.Telegram.ChatID != "") || n.Demo,
		"email":     (c.SMTP.Host != "" && len(c.SMTP.To) > 0) || n.Demo,
	}
}

// Send delivers to one channel.
func (n *Notifier) Send(channel string, m Message) error {
	if !n.Channels()[channel] {
		return fmt.Errorf("%s is not configured", channel)
	}
	if n.Demo || channel == "dashboard" {
		return nil
	}
	switch channel {
	case "webhook":
		return n.webhook(m)
	case "telegram":
		return n.telegram(m)
	case "email":
		return n.email(m)
	}
	return fmt.Errorf("unknown channel %q", channel)
}

var sevEmoji = map[string]string{"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}

func (n *Notifier) webhook(m Message) error {
	body := map[string]any{"title": m.Title, "message": m.Text, "severity": m.Severity, "host": m.Host, "ts": m.TS,
		// Slack / Discord / Mattermost compatible fields
		"text":    fmt.Sprintf("%s *%s* (%s)\n%s", sevEmoji[m.Severity], m.Title, m.Host, m.Text),
		"content": fmt.Sprintf("%s **%s** (%s)\n%s", sevEmoji[m.Severity], m.Title, m.Host, m.Text)}
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", n.cfg.Notify.Webhook.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "myowl")
	for k, v := range n.cfg.Notify.Webhook.Headers {
		req.Header.Set(k, v)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func (n *Notifier) telegram(m Message) error {
	t := n.cfg.Notify.Telegram
	text := fmt.Sprintf("%s %s\nServer: %s\n\n%s", sevEmoji[m.Severity], m.Title, m.Host, m.Text)
	b, _ := json.Marshal(map[string]any{"chat_id": t.ChatID, "text": text, "disable_web_page_preview": true})
	resp, err := n.client.Post("https://api.telegram.org/bot"+t.BotToken+"/sendMessage", "application/json", bytes.NewReader(b))
	if err != nil {
		// never leak the bot token in errors
		return errors.New("telegram request failed: " + strings.ReplaceAll(err.Error(), t.BotToken, "***"))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		var r struct{ Description string }
		_ = json.NewDecoder(resp.Body).Decode(&r)
		return fmt.Errorf("telegram: %s %s", resp.Status, r.Description)
	}
	return nil
}

func (n *Notifier) email(m Message) error {
	c := n.cfg.Notify.SMTP
	from := c.From
	if from == "" {
		from = c.Username
	}
	subject := fmt.Sprintf("[%s] %s: %s", strings.ToUpper(m.Severity), m.Host, m.Title)
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n\r\n-- \r\nmyOwl on %s\r\n",
		from, strings.Join(c.To, ", "), subject, time.Now().Format(time.RFC1123Z), m.Text, m.Host)
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	var auth smtp.Auth
	if c.Username != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}
	if c.Port == 465 {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, &tls.Config{ServerName: c.Host})
		if err != nil {
			return err
		}
		cl, err := smtp.NewClient(conn, c.Host)
		if err != nil {
			return err
		}
		defer cl.Close()
		if auth != nil {
			if err := cl.Auth(auth); err != nil {
				return err
			}
		}
		if err := cl.Mail(from); err != nil {
			return err
		}
		for _, to := range c.To {
			if err := cl.Rcpt(to); err != nil {
				return err
			}
		}
		w, err := cl.Data()
		if err != nil {
			return err
		}
		if _, err := w.Write(msg.Bytes()); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		return cl.Quit()
	}
	// smtp.SendMail uses STARTTLS when the server supports it
	return smtp.SendMail(addr, auth, from, c.To, msg.Bytes())
}
