package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"souben/kai/repo"
	"testing"
)

// MockRepository is a mock implementation of dbRepository
type MockRepository struct {
	savedVulnerabilities []repo.Vulnerabality
	vulnerabilitiesToReturn []repo.Vulnerabality
	err error
}

func (m *MockRepository) SaveVulnerabilities(ctx context.Context, vulnerabilities []repo.Vulnerabality) error {
	if m.err != nil {
		return m.err
	}
	m.savedVulnerabilities = append(m.savedVulnerabilities, vulnerabilities...)
	return nil
}

func (m *MockRepository) GetVulnerabilities(ctx context.Context, severity string) ([]repo.Vulnerabality, error) {
	if m.err != nil {
		return nil, m.err
	}

	var filtered []repo.Vulnerabality
	for _, v := range m.vulnerabilitiesToReturn {
		if v.Severity == severity {
			filtered = append(filtered, v)
		}
	}
	return filtered, nil
}

func (m *MockRepository) Close() error {
	return nil
}

// Test buildGitHubSearchURL function
func TestBuildGitHubSearchURL(t *testing.T) {
	tests := []struct {
		name     string
		repo     string
		files    []string
		expected string
	}{
		{
			name:     "With repo and files",
			repo:     "owner/repo",
			files:    []string{"file1", "file2"},
			expected: "https://api.github.com/search/code?q=repo:owner/repo+filename:file1.json+filename:file2.json",
		},
		{
			name:     "With repo but no files",
			repo:     "owner/repo",
			files:    []string{},
			expected: "https://api.github.com/search/code?q=repo:owner/repo+extension:json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGitHubSearchURL(tt.repo, tt.files)
			if result != tt.expected {
				t.Errorf("buildGitHubSearchURL() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Test Filter function
func TestFilter(t *testing.T) {
	// Create mock data
	mockVulnerabilities := []repo.Vulnerabality{
		{
			ID:          "CVE-2024-1234",
			Severity:    "HIGH",
			Description: "Test vulnerability 1",
		},
		{
			ID:          "CVE-2024-5678",
			Severity:    "MEDIUM",
			Description: "Test vulnerability 2",
		},
		{
			ID:          "CVE-2024-9012",
			Severity:    "HIGH",
			Description: "Test vulnerability 3",
		},
	}

	// Create mock repository
	mockRepo := &MockRepository{
		vulnerabilitiesToReturn: mockVulnerabilities,
	}

	// Set the database to our mock
	origDB := database
	database = mockRepo
	defer func() { database = origDB }()

	// Test filtering HIGH severity
	ctx := context.Background()
	result, err := Filter(ctx, "HIGH")
	if err != nil {
		t.Fatalf("Filter() error = %v", err)
	}

	// Should return 2 HIGH vulnerabilities
	if len(result) != 2 {
		t.Errorf("Filter() returned %d results, want 2", len(result))
	}

	// All should be HIGH severity
	for _, v := range result {
		if v.Severity != "HIGH" {
			t.Errorf("Filter() returned vulnerability with severity %s, want HIGH", v.Severity)
		}
	}

	// Test filtering MEDIUM severity
	result, err = Filter(ctx, "MEDIUM")
	if err != nil {
		t.Fatalf("Filter() error = %v", err)
	}

	// Should return 1 MEDIUM vulnerability
	if len(result) != 1 {
		t.Errorf("Filter() returned %d results, want 1", len(result))
	}

	// Test filtering LOW severity (should return empty)
	result, err = Filter(ctx, "LOW")
	if err != nil {
		t.Fatalf("Filter() error = %v", err)
	}

	// Should return 0 LOW vulnerabilities
	if len(result) != 0 {
		t.Errorf("Filter() returned %d results, want 0", len(result))
	}
}

// Mock HTTP server for GitHub API tests
func setupMockGitHubServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a search request
		if r.URL.Path == "/search/code" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{
				"total_count": 1,
				"items": [
					{
						"name": "test.json",
						"path": "test.json",
						"url": "/raw/test.json"
					}
				]
			}`))
			return
		}

		// Check if it's a raw file request
		if r.URL.Path == "/raw/test.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[
				{
					"scanResults": {
						"vulnerabilities": [
							{
								"id": "CVE-2024-1234",
								"severity": "HIGH",
								"cvss": 8.5,
								"status": "fixed",
								"package_name": "test-package",
								"current_version": "1.0.0",
								"fixed_version": "1.1.0",
								"description": "Test vulnerability",
								"published_date": "2024-01-01T00:00:00Z",
								"link": "https://example.com/cve",
								"risk_factors": ["Test Risk"]
							}
						]
					}
				}
			]`))
			return
		}

		// Default response for unknown paths
		w.WriteHeader(http.StatusNotFound)
	}))
}

// Test searchGitHubFiles function
func TestSearchGitHubFiles(t *testing.T) {
	// Set up a mock HTTP server
	server := setupMockGitHubServer()
	defer server.Close()

	// Save and restore the original GITHUB_API
	originalAPI := GITHUB_API
	GITHUB_API = server.URL + "/search/code"
	defer func() { GITHUB_API = originalAPI }()

	// Test the search function
	items, err := searchGitHubFiles(GITHUB_API+"?q=repo:test/repo", "test-token")
	if err != nil {
		t.Fatalf("searchGitHubFiles() error = %v", err)
	}

	// Check the results
	if len(items) != 1 {
		t.Fatalf("searchGitHubFiles() returned %d items, want 1", len(items))
	}

	if items[0].Name != "test.json" {
		t.Errorf("searchGitHubFiles() item name = %s, want test.json", items[0].Name)
	}
}