package repo

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

// Vulnerability represents a security vulnerability found in a scan
type Vulnerabality struct {
	ID             string    `json:"id"`
	Severity       string    `json:"severity"`
	Cvss           float64   `json:"cvss"`
	Status         string    `json:"status"`
	PackageName    string    `json:"package_name"`
	CurrentVersion string    `json:"current_version"`
	FixedVersion   string    `json:"fixed_version"`
	Description    string    `json:"description"`
	PublishedDate  time.Time `json:"published_date"`
	Link           string    `json:"link"`
	RiskFactors    []string  `json:"risk_factors"`

	// Metadata
	SourceFile string    `json:"source_file"`
	ScanTime   time.Time `json:"scan_time"`
}

// DatabaseConfig holds the configuration for the database connection
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
}

// PostgresRepo implements database operations for vulnerability data
type PostgresRepo struct {
	db *sql.DB
}

// NewPostgresRepo creates a new PostgreSQL repository
func NewPostgresRepo(config DatabaseConfig) (*PostgresRepo, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Host, config.Port, config.User, config.Password, config.DBName)

	db, err := sql.Open("postgres", connStr)

	if err != nil {
		return nil, err
	}

	// Test the connection
	err = db.Ping()

	if err != nil {
		return nil, err
	}

	// Ensure the database schema exists
	err = initSchema(db)
	if err != nil {
		return nil, err
	}

	return &PostgresRepo{db: db}, nil
}

// Close closes the database connection
func (r *PostgresRepo) Close() error {
	return r.db.Close()
}

// SaveVulnerabilities stores a batch of vulnerabilities in the database
func (r *PostgresRepo) SaveVulnerabilities(ctx context.Context, vulnerabilities []Vulnerabality) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO vulnerabilities (
			id, severity, cvss, status, package_name, current_version, 
			fixed_version, description, published_date, link, risk_factors, 
			source_file, scan_time
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		) ON CONFLICT (id, source_file) 
		DO UPDATE SET 
			severity = $2, cvss = $3, status = $4, package_name = $5,
			current_version = $6, fixed_version = $7, description = $8,
			published_date = $9, link = $10, risk_factors = $11, scan_time = $13
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, vuln := range vulnerabilities {
		_, err = stmt.ExecContext(
			ctx,
			vuln.ID, vuln.Severity, vuln.Cvss, vuln.Status, vuln.PackageName,
			vuln.CurrentVersion, vuln.FixedVersion, vuln.Description, vuln.PublishedDate,
			vuln.Link, pq.Array(vuln.RiskFactors), vuln.SourceFile, vuln.ScanTime,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetVulnerabilities retrieves vulnerabilities from the database
func (r *PostgresRepo) GetVulnerabilities(ctx context.Context, severity string) ([]Vulnerabality, error) {
	query := `
		SELECT id, severity, cvss, status, package_name, current_version, 
			fixed_version, description, published_date, link, risk_factors, 
			source_file, scan_time 
		FROM vulnerabilities 
		WHERE severity=$1 
		ORDER BY scan_time DESC 
	`

	rows, err := r.db.QueryContext(ctx, query, severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulnerabilities []Vulnerabality

	for rows.Next() {
		var vuln Vulnerabality
		err := rows.Scan(
			&vuln.ID, &vuln.Severity, &vuln.Cvss, &vuln.Status, &vuln.PackageName,
			&vuln.CurrentVersion, &vuln.FixedVersion, &vuln.Description, &vuln.PublishedDate,
			&vuln.Link, pq.Array(&vuln.RiskFactors), &vuln.SourceFile, &vuln.ScanTime,
		)
		if err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

// initSchema creates the necessary database tables if they don't exist
func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			id VARCHAR(255) NOT NULL,
			severity VARCHAR(50) NOT NULL,
			cvss DECIMAL(4,1) NOT NULL,
			status VARCHAR(50) NOT NULL,
			package_name VARCHAR(255) NOT NULL,
			current_version VARCHAR(50) NOT NULL,
			fixed_version VARCHAR(50),
			description TEXT NOT NULL,
			published_date TIMESTAMP NOT NULL,
			link TEXT,
			risk_factors TEXT[],
			source_file VARCHAR(255) NOT NULL,
			scan_time TIMESTAMP NOT NULL,
			PRIMARY KEY (id, source_file)
		)
	`)

	return err
}
