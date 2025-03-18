package repo

import "time"

// SearchResponse represents the response from GitHub API search
type SearchResponse struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Name string `json:"name"`
		Path string `json:"path"`
		URL  string `json:"url"`
	} `json:"items"`
}

// ScanResult represents the result of a scan operation
type ScanResult struct {
	ProcessedFiles int       `json:"processed_files"`
	ScanTime       time.Time `json:"scan_time"`
	SourceRepo     string    `json:"source_repo"`
	SourceFiles    []string  `json:"source_files"`
}

// ScanPayload represents the structure of the JSON files
type ScanPayloads struct {
	ScanResults struct {
		Vulnerabilities []Vulnerabality `json:"vulnerabilities"`
	} `json:"scanResults"`
}

// ScanRequest defines the expected body in the request for the scan endpoint
type ScanRequestBody struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}
