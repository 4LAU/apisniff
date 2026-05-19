package replay

import "testing"

func TestCompareShapeMatchesJSONStructureToDepth(t *testing.T) {
	original := []byte(`{"items":[{"id":1,"profile":{"name":"a","extra":{"deep":1}}}],"ok":true}`)
	replayed := []byte(`{"items":[{"id":2,"profile":{"name":"b","extra":{"deep":"changed"}}}],"ok":false}`)

	match, diff := CompareShape(original, replayed)
	if !match {
		t.Fatalf("expected shape match, diff = %#v", diff)
	}
}

func TestCompareShapeDetectsDrift(t *testing.T) {
	match, diff := CompareShape([]byte(`{"id":1,"name":"a"}`), []byte(`{"id":1,"email":"a@example.com"}`))
	if match {
		t.Fatalf("expected drift")
	}
	if diff["name"] == nil || diff["email"] == nil {
		t.Fatalf("diff = %#v", diff)
	}
}

func TestAssignCategory(t *testing.T) {
	tests := []struct {
		name   string
		status int
		auth   bool
		body   bool
		want   string
	}{
		{name: "match", status: 200, body: true, want: "match"},
		{name: "drift", status: 201, body: true, want: "drift"},
		{name: "auth expired", status: 401, auth: true, body: true, want: "auth_expired"},
		{name: "blocked", status: 403, body: true, want: "blocked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := AssignCategory(200, tt.status, tt.auth, tt.body, 10, 10, nil)
			if got != tt.want {
				t.Fatalf("category = %q, want %q", got, tt.want)
			}
		})
	}
}
