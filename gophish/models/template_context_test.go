package models

import (
	"fmt"
	"net/url"

	check "gopkg.in/check.v1"
)

type mockTemplateContext struct {
	URL           string
	FromAddress   string
	EncryptionKey string
}

func (m mockTemplateContext) getFromAddress() string {
	return m.FromAddress
}

func (m mockTemplateContext) getBaseURL() string {
	return m.URL
}

func (m mockTemplateContext) getEncryptionKey() string {
	return m.EncryptionKey
}

func (s *ModelsSuite) TestNewTemplateContext(c *check.C) {
	r := Result{
		BaseRecipient: BaseRecipient{
			FirstName: "Foo",
			LastName:  "Bar",
			Email:     "foo@bar.com",
		},
		RId: "1234567",
	}
	ctx := mockTemplateContext{
		URL:           "http://example.com",
		FromAddress:   "From Address <from@example.com>",
		EncryptionKey: "",
	}
	// When EncryptionKey is empty, AddPhishUrlParams appends all recipient
	// fields (email, fname, lname, rid) as plain query parameters. The
	// tracking URL uses ?o=track&rid= (query-based) not /track?rid= (path-based).
	phishParams := url.Values{}
	phishParams.Set("email", r.Email)
	phishParams.Set("fname", r.FirstName)
	phishParams.Set("lname", r.LastName)
	phishParams.Set("rid", r.RId)

	trackParams := url.Values{}
	trackParams.Set("o", "track")
	trackParams.Set("rid", r.RId)

	expectedURL := fmt.Sprintf("%s?%s", ctx.URL, phishParams.Encode())
	expectedTrackingURL := fmt.Sprintf("%s?%s", ctx.URL, trackParams.Encode())

	expected := PhishingTemplateContext{
		URL:           expectedURL,
		BaseURL:       ctx.URL,
		BaseRecipient: r.BaseRecipient,
		TrackingURL:   expectedTrackingURL,
		From:          "From Address",
		RId:           r.RId,
	}
	expected.Tracker = "<img alt='' style='display: none' src='" + expected.TrackingURL + "'/>"
	got, err := NewPhishingTemplateContext(ctx, r.BaseRecipient, r.RId)
	c.Assert(err, check.Equals, nil)
	c.Assert(got, check.DeepEquals, expected)
}
