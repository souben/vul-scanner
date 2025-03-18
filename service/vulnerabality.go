package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"souben/kai/repo"

	"github.com/joho/godotenv"
)

// Helper functions for environment variables
func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvAsIntOrDefault(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	var result int
	fmt.Sscanf(value, "%d", &result)
	return result
}

var (
	GITHUB_API  = getEnvOrDefault("GITHUB_API", "https://api.github.com/search/code")
	MAX_RETRIES = getEnvAsIntOrDefault("MAX_RETRIES", 2)
	CONCURRENCY = getEnvAsIntOrDefault("CONCURRENCY", 3)
)

// init is invoked before main()
func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

// dbRepository provides an interface for database operations
type dbRepository interface {
	SaveVulnerabilities(ctx context.Context, vulnerabilities []repo.Vulnerabality) error
	GetVulnerabilities(ctx context.Context, severity string) ([]repo.Vulnerabality, error)
	Close() error
}

var (
	database dbRepository
)

// InitDatabase initializes the database connection
func InitDatabase() error {
	// Get database configuration from environment variables
	dbConfig := repo.DatabaseConfig{
		Host:     getEnvOrDefault("DB_HOST", "localhost"),
		Port:     getEnvAsIntOrDefault("DB_PORT", 5432),
		User:     getEnvOrDefault("DB_USER", "postgres"),
		Password: getEnvOrDefault("DB_PASSWORD", "postgres"),
		DBName:   getEnvOrDefault("DB_NAME", ""),
	}

	// Create a new database connection
	var err error
	db, err := repo.NewPostgresRepo(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	database = db
	return nil
}

// CloseDatabase closes the database connection
func CloseDatabase() error {
	if database != nil {
		return database.Close()
	}
	return nil
}

// Scan scans a GitHub repository for vulnerability data in JSON files
func Scan(repoName string, filenames []string) (*repo.ScanResult, error) {
	ctx := context.Background()

	// Check if database is initialized
	if database == nil {
		if err := InitDatabase(); err != nil {
			return nil, err
		}
	}

	// Get GitHub token from environment
	token := os.Getenv("GITHUB_API_TOKEN")
	if token == "" {
		return nil, errors.New("GitHub token not found in environment variables")
	}

	// Construct the URL for the GitHub API call
	url := buildGitHubSearchURL(repoName, filenames)

	// Search for JSON files in the repository
	items, err := searchGitHubFiles(url, token)
	if err != nil {
		return nil, err
	}

	if len(items) == 0 {
		log.Print("No items were found!")
		return &repo.ScanResult{
			ProcessedFiles: 0,
			ScanTime:       time.Now(),
			SourceRepo:     repoName,
			SourceFiles:    []string{},
		}, nil
	}

	// Process files concurrently
	result, err := processFilesInParallel(ctx, items, token, repoName)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// buildGitHubSearchURL constructs the URL for the GitHub API search
func buildGitHubSearchURL(repo string, filenames []string) string {
	if repo == "" {
		log.Fatal("You should provide a repository name!")
	}

	url := fmt.Sprintf("%s?q=repo:%s", GITHUB_API, repo)

	// If filenames were provided, search exactly for those files
	for _, filename := range filenames {
		url = fmt.Sprintf("%s+filename:%s.json", url, filename)
	}

	// If no filenames are provided, search for all JSON files within the repository
	if len(filenames) == 0 {
		url = fmt.Sprintf("%s+extension:json", url)
	}

	return url
}

// searchGitHubFiles performs a GitHub API search for files
func searchGitHubFiles(url, token string) ([]struct {
	Name string `json:"name"`
	Path string `json:"path"`
	URL  string `json:"url"`
}, error) {

	var response repo.SearchResponse

	// Implement retry logic for GitHub API calls
	var err error
	for attempt := 0; attempt <= MAX_RETRIES; attempt++ {
		if attempt > 0 {
			log.Printf("Retrying GitHub API call (attempt %d/%d)", attempt, MAX_RETRIES)
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		client := &http.Client{Timeout: 10 * time.Second}
		res, err := client.Do(req)
		if err != nil {
			continue
		}

		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			data, _ := io.ReadAll(res.Body)
			err = fmt.Errorf("GitHub API returned status %d: %s", res.StatusCode, string(data))
			continue
		}

		data, err := io.ReadAll(res.Body)
		if err != nil {
			continue
		}

		err = json.Unmarshal(data, &response)
		if err != nil {
			continue
		}

		// fetched succefully the files urls
		return response.Items, nil
	}

	return nil, fmt.Errorf("failed to search GitHub files after %d attempts: %w", MAX_RETRIES+1, err)
}

// processFilesInParallel processes multiple files concurrently
func processFilesInParallel(ctx context.Context, items []struct {
	Name string `json:"name"`
	Path string `json:"path"`
	URL  string `json:"url"`
}, token, repoName string) (*repo.ScanResult, error) {
	var (
		wg             sync.WaitGroup
		mu             sync.Mutex
		processedFiles []string
		errorsOccurred []error
		// Use this channel to make share that a limited of gourotines is created
		pool = make(chan struct{}, CONCURRENCY)
	)
	for _, item := range items {
		wg.Add(1)

		// The code will block here is we already have a number of goroutines == CONCURRENCY
		pool <- struct{}{}

		go func(item struct {
			Name string `json:"name"`
			Path string `json:"path"`
			URL  string `json:"url"`
		}) {
			defer wg.Done()
			defer func() { <-pool }() // once the goroutine is done, we will decrement the count of goroutines created

			err := processFile(ctx, item, token, repoName)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errorsOccurred = append(errorsOccurred, fmt.Errorf("error processing %s: %w", item.Path, err))
				return
			}

			processedFiles = append(processedFiles, item.Path)
		}(item)
	}

	wg.Wait()

	// If all files failed, return an error
	if len(errorsOccurred) == len(items) {
		return nil, fmt.Errorf("all files failed to process: %v", errorsOccurred[0])
	}

	// Return the scan results
	result := &repo.ScanResult{
		ProcessedFiles: len(processedFiles),
		ScanTime:       time.Now(),
		SourceRepo:     repoName,
		SourceFiles:    processedFiles,
	}

	return result, nil
}

// processFile processes a single file and returns the vulnerabalities found
func processFile(ctx context.Context, item struct {
	Name string `json:"name"`
	Path string `json:"path"`
	URL  string `json:"url"`
}, token, repoName string) error {
	var vulnerabilities []repo.Vulnerabality

	// Implement retry logic for GitHub API calls
	var data []byte
	var err error

	for attempt := 0; attempt <= MAX_RETRIES; attempt++ {
		if attempt > 0 {
			log.Printf("Retrying file download for %s (attempt %d/%d)", item.Path, attempt, MAX_RETRIES)
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequest("GET", item.URL, bytes.NewBuffer([]byte{}))
		if err != nil {
			continue
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		// The GitHub API will return a JSON response with the content as a field encoded in base64.
		// We set the header to `application/vnd.github.v3.raw` so we can get the file's raw content
		req.Header.Set("Accept", "application/vnd.github.v3.raw")

		client := &http.Client{Timeout: 10 * time.Second}

		res, err := client.Do(req)
		if err != nil {
			continue
		}

		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			bodyData, _ := io.ReadAll(res.Body)
			err = fmt.Errorf("GitHub API returned status %d: %s", res.StatusCode, string(bodyData))
			continue
		}

		data, err = io.ReadAll(res.Body)
		if err != nil {
			continue
		}

		// Successfully processed the file
		break
	}

	if err != nil {
		return fmt.Errorf("failed to download file after %d attempts: %w", MAX_RETRIES+1, err)
	}

	// Parse the file content
	var fileContent []repo.ScanPayloads
	err = json.Unmarshal(data, &fileContent)
	println(string(data))

	if err != nil {
		return fmt.Errorf("FFFFailed to parse file: %w %v", err, string(data))
	}

	// Process the vulnerabilities
	scanTime := time.Now()
	for _, scanResult := range fileContent {
		if len(scanResult.ScanResults.Vulnerabilities) == 0 {
			continue
		}
		for _, payload := range scanResult.ScanResults.Vulnerabilities {
			// Add metadata to each vulnerability
			payload.SourceFile = item.Path
			payload.ScanTime = scanTime
			vulnerabilities = append(vulnerabilities, payload)
		}
	}

	// Store vulnerabilities in the database
	if len(vulnerabilities) > 0 {

		err = database.SaveVulnerabilities(ctx, vulnerabilities)
		if err != nil {
			return fmt.Errorf("failed to save vulnerabilities: %w", err)
		}
	}

	return nil
}

// Exract all the payloads based on a specific severity
func Filter(ctx context.Context, severity string) ([]repo.Vulnerabality, error) {

	// Check if the database is already set
	if database == nil {
		if err := InitDatabase(); err != nil {
			return nil, err
		}
	}

	// Get the vulnerabilities based on severity
	vulnerabilities, err := database.GetVulnerabilities(ctx, severity)
	if err != nil {
		return []repo.Vulnerabality{}, nil
	}

	return vulnerabilities, nil
}
