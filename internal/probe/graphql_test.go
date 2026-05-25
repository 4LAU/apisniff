package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckIntrospectionRequiresSchemaData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"errors":[{"message":"Cannot query field \"__schema\""}]}`))
	}))
	defer server.Close()

	client := &http.Client{Timeout: time.Second}
	if checkIntrospection(context.Background(), client, server.URL, Options{}) {
		t.Fatalf("error response was treated as enabled introspection")
	}
}

func TestDetectGraphQLRequiresTypenameData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if strings.Contains(r.URL.Path, "graphql") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"errors":[{"message":"Cannot query field \"__typename\""}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	result := DetectGraphQL(context.Background(), server.URL, Options{Timeout: time.Second})
	if len(result.Endpoints) != 0 || result.Introspection {
		t.Fatalf("graphql detection = %#v", result)
	}
}
