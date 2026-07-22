package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendReportPostsJSONAndToken(t *testing.T) {
	var gotToken string
	var gotReport Report

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Inventory-Token")
		if err := json.NewDecoder(r.Body).Decode(&gotReport); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	report := Report{Hostname: "test-host", ClientVersion: "0.1.0"}
	err := SendReport(server.URL, "secret-token", report)

	if err != nil {
		t.Fatalf("SendReport() error = %v", err)
	}
	if gotToken != "secret-token" {
		t.Errorf("token header = %q, want %q", gotToken, "secret-token")
	}
	if gotReport.Hostname != "test-host" {
		t.Errorf("hostname = %q, want %q", gotReport.Hostname, "test-host")
	}
}

func TestSendReportNoTokenOmitsHeader(t *testing.T) {
	var headerPresent bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, headerPresent = r.Header["X-Inventory-Token"]
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := SendReport(server.URL, "", Report{Hostname: "test-host"})
	if err != nil {
		t.Fatalf("SendReport() error = %v", err)
	}
	if headerPresent {
		t.Error("token header present, want absent when token is empty")
	}
}

func TestSendReportServerErrorReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	err := SendReport(server.URL, "", Report{Hostname: "test-host"})
	if err == nil {
		t.Fatal("SendReport() error = nil, want an error for HTTP 400")
	}
}
