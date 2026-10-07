package client

import (
	"context"
	"errors"
	"net/url"
	"strconv"

	"github.com/tropeforce7/agentuucp/internal/relayapi"
	"github.com/tropeforce7/agentuucp/internal/token"
)

// The administration half of the relay API.
//
// Every call here is signed with the caller's identity exactly like any other
// request. What makes it an administrator's call is that the relay's host
// listed that identity in its authorized file; the client does not know or
// need to know whether it will be allowed.

// AdminStatus reports what the relay is doing.
func (c *Client) AdminStatus(ctx context.Context) (*relayapi.AdminStatusResponse, error) {
	var out relayapi.AdminStatusResponse
	if err := c.do(ctx, "GET", "/v1/admin/status", nil, &out, nil); err != nil {
		return nil, err
	}
	if err := c.checkStatus(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdminMailboxes returns one page of mailboxes, starting after the given
// fingerprint. An empty after starts at the beginning.
func (c *Client) AdminMailboxes(ctx context.Context, after string, limit int) (*relayapi.MailboxListResponse, error) {
	q := url.Values{}
	if after != "" {
		q.Set("after", after)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := "/v1/admin/mailboxes"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out relayapi.MailboxListResponse
	if err := c.do(ctx, "GET", path, nil, &out, nil); err != nil {
		return nil, err
	}
	if err := c.checkMailboxes(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdminMailbox returns one mailbox.
func (c *Client) AdminMailbox(ctx context.Context, fp string) (*relayapi.MailboxRecord, error) {
	var answer relayapi.MailboxAnswer
	if err := c.do(ctx, "GET", "/v1/admin/mailboxes/"+fp, nil, &answer, nil); err != nil {
		return nil, err
	}
	out := answer.Mailbox
	if err := c.checkMailbox("the mailbox", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdminDeregister removes a mailbox and everything queued for it.
func (c *Client) AdminDeregister(ctx context.Context, fp string) error {
	return c.do(ctx, "DELETE", "/v1/admin/mailboxes/"+fp, nil, nil, nil)
}

// AdminPurge drops everything queued for a mailbox, leaving the mailbox.
func (c *Client) AdminPurge(ctx context.Context, fp string) error {
	return c.do(ctx, "DELETE", "/v1/admin/mailboxes/"+fp+"/messages", nil, nil, nil)
}

// AdminBlocks lists every blocked identity.
func (c *Client) AdminBlocks(ctx context.Context) ([]relayapi.BlockRecord, error) {
	var out relayapi.BlocksResponse
	if err := c.do(ctx, "GET", "/v1/admin/blocks", nil, &out, nil); err != nil {
		return nil, err
	}
	if err := c.checkBlocks(out.Blocks); err != nil {
		return nil, err
	}
	return out.Blocks, nil
}

// AdminBlock bars an identity from the relay.
func (c *Client) AdminBlock(ctx context.Context, fp, reason string) error {
	return c.do(ctx, "PUT", "/v1/admin/blocks/"+fp, relayapi.BlockRequest{Reason: reason}, nil, nil)
}

// AdminUnblock lifts a block.
func (c *Client) AdminUnblock(ctx context.Context, fp string) error {
	return c.do(ctx, "DELETE", "/v1/admin/blocks/"+fp, nil, nil, nil)
}

// AdminAddToken registers an enrolment token this identity signed.
func (c *Client) AdminAddToken(ctx context.Context, tok string) (*relayapi.TokenRecord, error) {
	var answer relayapi.TokenAnswer
	if err := c.do(ctx, "POST", "/v1/admin/tokens",
		relayapi.RegisterTokenRequest{Token: tok}, &answer, nil); err != nil {
		return nil, err
	}
	out := answer.Token
	if err := c.checkToken("the registered token", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AdminTokens lists registered tokens. all includes the spent, revoked and
// expired ones.
func (c *Client) AdminTokens(ctx context.Context, all bool) ([]relayapi.TokenRecord, error) {
	path := "/v1/admin/tokens"
	if all {
		path += "?all=1"
	}
	var out relayapi.TokenListResponse
	if err := c.do(ctx, "GET", path, nil, &out, nil); err != nil {
		return nil, err
	}
	if err := c.checkTokens(out.Tokens); err != nil {
		return nil, err
	}
	return out.Tokens, nil
}

// AdminRevokeToken withdraws a token. The id is held to its shape before
// it is joined onto the path, as a fingerprint is: a value with a slash
// or a question mark in it would be two segments or a query.
func (c *Client) AdminRevokeToken(ctx context.Context, id string) error {
	if !token.ValidID(id) {
		return errors.New("token id must be 32 lowercase hex characters")
	}
	return c.do(ctx, "DELETE", "/v1/admin/tokens/"+id, nil, nil, nil)
}

// AdminCerts lists issued client certificates, for one identity when fp is
// given. all includes the revoked and expired ones.
func (c *Client) AdminCerts(ctx context.Context, fp string, all bool) ([]relayapi.CertRecord, error) {
	path := "/v1/admin/certs"
	q := url.Values{}
	if fp != "" {
		q.Set("fp", fp)
	}
	if all {
		q.Set("all", "true")
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out relayapi.CertsResponse
	if err := c.do(ctx, "GET", path, nil, &out, nil); err != nil {
		return nil, err
	}
	if err := c.checkCerts("the certificate listing", out.Certs, false); err != nil {
		return nil, err
	}
	return out.Certs, nil
}

// AdminRevokeCert withdraws one client certificate. The machine holding it
// loses the relay on its next request.
func (c *Client) AdminRevokeCert(ctx context.Context, serial, reason string) error {
	return c.do(ctx, "DELETE", "/v1/admin/certs/"+serial,
		relayapi.RevokeCertRequest{Reason: reason}, nil, nil)
}
