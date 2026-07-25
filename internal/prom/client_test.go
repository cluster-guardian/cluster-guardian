package prom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryVector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query().Get("query"); q != "up" {
			t.Errorf("unexpected query %q", q)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"namespace":"payments","pod":"api-1"},"value":[1721300000,"0.25"]},
			{"metric":{"namespace":"payments","pod":"api-2"},"value":[1721300000,"0.75"]}
		]}}`))
	}))
	defer srv.Close()

	samples, err := NewClient(srv.URL).QueryVector(context.Background(), "up")
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(samples))
	}
	if samples[0].Labels["pod"] != "api-1" || samples[0].Value != 0.25 {
		t.Errorf("unexpected sample: %+v", samples[0])
	}
}

func TestQueryVectorError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","error":"bad query"}`))
	}))
	defer srv.Close()

	if _, err := NewClient(srv.URL).QueryVector(context.Background(), "up"); err == nil {
		t.Error("expected an error for a failed query")
	}
}
