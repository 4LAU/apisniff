package adapter

import (
	"os"
	"path/filepath"
	"testing"
)

const reqB64 = "UE9TVCAvYXBpL2l0ZW1zP3BhZ2U9MSBIVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS5jb20NCkF1dGhvcml6YXRpb246IEJlYXJlciB0b2tlbjEyMw0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uDQoNCnsibmFtZSI6ICJ3aWRnZXQifQ=="
const respB64 = "SFRUUC8xLjEgMjAxIENyZWF0ZWQNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbg0KWC1SZXF1ZXN0LUlkOiBhYmMxMjMNCg0KeyJpZCI6IDF9"
const cookieRespB64 = "SFRUUC8xLjEgMjAxIENyZWF0ZWQNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbg0KU2V0LUNvb2tpZTogc2Vzc2lvbj1hYmMNClNldC1Db29raWU6IGNzcmY9eHl6DQoNCnsiaWQiOiAxfQ=="

func TestBurpConversion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "burp.xml")
	xml := `<?xml version="1.0"?><items>
		<item><method>POST</method><url>https://example.com/api/items?page=1</url><status>201</status><request base64="true">` + reqB64 + `</request><response base64="true">` + respB64 + `</response></item>
		<item><method>GET</method><url>https://example.com/health</url><status>200</status><request>GET /health HTTP/1.1&#13;&#10;Host: example.com&#13;&#10;X-Custom: hello&#13;&#10;&#13;&#10;</request><response>HTTP/1.1 200 OK&#13;&#10;Content-Type: text/plain&#13;&#10;&#13;&#10;ok</response></item>
		<item><method>POST</method><url>https://example.com/cookie</url><status>201</status><request /><response base64="true">` + cookieRespB64 + `</response></item>
	</items>`
	if err := os.WriteFile(path, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	flows, err := LoadBurp(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 3 {
		t.Fatalf("flows = %d", len(flows))
	}
	first := flows[0]
	if first.Method != "POST" || first.Path != "/api/items?page=1" || first.ResponseStatus != 201 {
		t.Fatalf("first = %+v", first)
	}
	if first.RequestHeaders["authorization"] != "Bearer token123" || first.ResponseHeaders["x-request-id"] != "abc123" {
		t.Fatalf("headers = %+v %+v", first.RequestHeaders, first.ResponseHeaders)
	}
	if string(first.RequestBody) != `{"name": "widget"}` || string(first.ResponseBody) != `{"id": 1}` {
		t.Fatalf("bodies = %q %q", first.RequestBody, first.ResponseBody)
	}
	if flows[1].RequestHeaders["x-custom"] != "hello" || string(flows[1].ResponseBody) != "ok" {
		t.Fatalf("plain = %+v %q", flows[1].RequestHeaders, flows[1].ResponseBody)
	}
	if flows[2].ResponseHeaders["set-cookie"] != "session=abc\ncsrf=xyz" {
		t.Fatalf("set-cookie = %q", flows[2].ResponseHeaders["set-cookie"])
	}
}

func TestBurpSkipsItemsWithoutAbsoluteURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "burp.xml")
	xml := `<?xml version="1.0"?><items>
		<item><method>GET</method><url>/relative</url><status>200</status><request /><response /></item>
		<item><method>GET</method><url>https://example.com/ok</url><status>200</status><request /><response /></item>
	</items>`
	if err := os.WriteFile(path, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	flows, err := LoadBurp(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || flows[0].URL != "https://example.com/ok" {
		t.Fatalf("flows = %#v", flows)
	}
}
