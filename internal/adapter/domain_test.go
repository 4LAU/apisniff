package adapter

import (
	"testing"

	"github.com/4LAU/apisniff/internal/model"
)

func TestAutoDetectDomainPicks2xLeader(t *testing.T) {
	flows := []model.CapturedFlow{
		{Host: "api.mysite.com"},
		{Host: "cdn.mysite.com"},
		{Host: "cdn.mysite.com"},
		{Host: "other.com"},
	}
	d := AutoDetectDomain(flows)
	if d.Domain != "mysite.com" {
		t.Fatalf("domain = %q, want mysite.com", d.Domain)
	}
	if d.Ambiguous {
		t.Fatal("expected non-ambiguous")
	}
}

func TestAutoDetectDomainAmbiguous(t *testing.T) {
	flows := []model.CapturedFlow{
		{Host: "a.com"},
		{Host: "b.com"},
	}
	d := AutoDetectDomain(flows)
	if !d.Ambiguous {
		t.Fatalf("expected ambiguous, got domain=%q count=%d second=%d", d.Domain, d.Count, d.SecondCount)
	}
}

func TestAutoDetectDomainEmpty(t *testing.T) {
	d := AutoDetectDomain(nil)
	if d.Domain != "" {
		t.Fatalf("domain = %q, want empty", d.Domain)
	}
}

func TestAutoDetectDomainURLFallback(t *testing.T) {
	flows := []model.CapturedFlow{
		{URL: "https://api.example.com/v1/users"},
		{URL: "https://cdn.example.com/asset.png"},
	}
	d := AutoDetectDomain(flows)
	if d.Domain != "example.com" {
		t.Fatalf("domain = %q, want example.com", d.Domain)
	}
}

func TestAutoDetectDomainInternational(t *testing.T) {
	flows := []model.CapturedFlow{
		{Host: "shop.example.co.uk"},
		{Host: "api.example.co.uk"},
		{Host: "cdn.example.co.uk"},
	}
	d := AutoDetectDomain(flows)
	if d.Domain != "example.co.uk" {
		t.Fatalf("domain = %q, want example.co.uk", d.Domain)
	}
}

func TestAutoDetectDomainHostedPlatform(t *testing.T) {
	flows := []model.CapturedFlow{
		{Host: "myapp.herokuapp.com"},
		{Host: "myapp.herokuapp.com"},
	}
	d := AutoDetectDomain(flows)
	if d.Domain != "myapp.herokuapp.com" {
		t.Fatalf("domain = %q, want myapp.herokuapp.com", d.Domain)
	}
}
