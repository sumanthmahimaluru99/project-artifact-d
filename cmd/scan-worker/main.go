package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	minioEndpoint  = "localhost:9000"
	minioAccessKey = "minioadmin"
	minioSecretKey = "minioadmin"
	bucketName     = "artifacts"
)

func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
func extractTarGz(sourceFile string, destinationDir string) error {
	file, err := os.Open(sourceFile)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		targetPath := filepath.Join(destinationDir, header.Name)

		switch header.Typeflag {

		case tar.TypeDir:
			err = os.MkdirAll(targetPath, 0755)
			if err != nil {
				return err
			}

		case tar.TypeReg:
			err = os.MkdirAll(filepath.Dir(targetPath), 0755)
			if err != nil {
				return err
			}

			outFile, err := os.Create(targetPath)
			if err != nil {
				return err
			}

			_, err = io.Copy(outFile, tarReader)
			outFile.Close()

			if err != nil {
				return err
			}
		}
	}

	return nil
}

type TrivyReport struct {
	Results []struct {
		Target string `json:"Target"`

		Packages []struct {
			ID           string `json:"ID"`
			Name         string `json:"Name"`
			Version      string `json:"Version"`
			Indirect     bool   `json:"Indirect"`
			Relationship string `json:"Relationship"`
		} `json:"Packages"`

		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func main() {

	ctx := context.Background()

	// Connect to PostgreSQL
	conn, err := pgx.Connect(
		ctx,
		"postgres://artifact:artifactpass@localhost:5432/artifactdb",
	)

	if err != nil {
		fmt.Println("Failed to connect to PostgreSQL:", err)
		return
	}

	defer conn.Close(ctx)

	fmt.Println("Scan Worker started")
	fmt.Println("Connected to PostgreSQL")

	// Find one RECEIVED artifact
	var artifactID string
	var storageBucket string
	var storageKey string
	var originalHash string

	err = conn.QueryRow(
		ctx,
		`
		SELECT artifact_id, storage_bucket, storage_key, sha256
        FROM artifacts
        WHERE status = 'RECEIVED'
        ORDER BY created_at DESC
        LIMIT 1
		`,
	).Scan(
		&artifactID,
		&storageBucket,
		&storageKey,
		&originalHash,
	)

	if err != nil {
		fmt.Println("No RECEIVED artifact found")
		return
	}

	fmt.Println("Found artifact:", artifactID)
	fmt.Println("Bucket:", storageBucket)
	fmt.Println("Object:", storageKey)

	// Change status to SCANNING
	_, err = conn.Exec(
		ctx,
		`
		UPDATE artifacts
		SET status = 'SCANNING'
		WHERE artifact_id = $1
		`,
		artifactID,
	)

	if err != nil {
		fmt.Println("Failed to update status:", err)
		return
	}

	fmt.Println("Artifact status changed to SCANNING")

	// Connect to MinIO
	minioClient, err := minio.New(
		minioEndpoint,
		&minio.Options{
			Creds: credentials.NewStaticV4(
				minioAccessKey,
				minioSecretKey,
				"",
			),
			Secure: false,
		},
	)

	if err != nil {
		fmt.Println("Failed to connect to MinIO:", err)
		return
	}

	fmt.Println("Connected to MinIO")

	// Get artifact from MinIO
	object, err := minioClient.GetObject(
		ctx,
		storageBucket,
		storageKey,
		minio.GetObjectOptions{},
	)

	if err != nil {
		fmt.Println("Failed to get artifact from MinIO:", err)
		return
	}

	defer object.Close()

	// Save downloaded artifact locally
	localFile := "/tmp/" + artifactID

	file, err := os.Create(localFile)
	if err != nil {
		fmt.Println("Failed to create local file:", err)
		return
	}

	defer file.Close()

	_, err = io.Copy(file, object)
	if err != nil {
		fmt.Println("Failed to download artifact:", err)
		return
	}

	fmt.Println("Artifact downloaded from MinIO")
	fmt.Println("Local file:", localFile)

	currentHash, err := calculateSHA256(localFile)
	if err != nil {
		fmt.Println("Failed to calculate downloaded SHA-256:", err)
		return
	}

	fmt.Println("Original SHA-256:", originalHash)
	fmt.Println("Downloaded SHA-256:", currentHash)

	if currentHash != originalHash {
		fmt.Println("INTEGRITY CHECK FAILED")

		_, err = conn.Exec(
			ctx,
			`
        UPDATE artifacts
        SET status = 'INTEGRITY_FAILED'
        WHERE artifact_id = $1
        `,
			artifactID,
		)

		if err != nil {
			fmt.Println("Failed to update integrity status:", err)
		}

		return
	}

	fmt.Println("INTEGRITY CHECK PASSED")

	// Malware scan with ClamAV
	clamCmd := exec.Command(
		"clamscan",
		"--no-summary",
		localFile,
	)

	clamOutput, clamErr := clamCmd.CombinedOutput()

	if clamErr != nil {
		fmt.Println("ClamAV detected malware or scan failed:")
		fmt.Println(string(clamOutput))

		_, err = conn.Exec(
			ctx,
			`
        UPDATE artifacts
        SET status = 'MALWARE_FOUND'
        WHERE artifact_id = $1
        `,
			artifactID,
		)

		if err != nil {
			fmt.Println("Failed to update malware status:", err)
		}

		return
	}

	fmt.Println("ClamAV scan passed")
	fmt.Println(string(clamOutput))

	scanDir := "/tmp/scan-" + artifactID

	err = os.RemoveAll(scanDir)
	if err != nil {
		fmt.Println("Failed to clean scan directory:", err)
		return
	}

	err = os.MkdirAll(scanDir, 0755)
	if err != nil {
		fmt.Println("Failed to create scan directory:", err)
		return
	}

	err = extractTarGz(localFile, scanDir)
	if err != nil {
		fmt.Println("Failed to extract artifact:", err)
		return
	}

	fmt.Println("Artifact extracted successfully")
	fmt.Println("Scan directory:", scanDir)

	cmd := exec.Command(
		"trivy",
		"fs",
		"--format",
		"json",
		scanDir,
	)

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Trivy scan failed:", err)
		return
	}

	fmt.Println("Trivy scan completed")

	var report TrivyReport

	err = json.Unmarshal(output, &report)

	for _, result := range report.Results {

		for _, pkg := range result.Packages {

			// Skip the root application itself
			if pkg.Relationship == "root" {
				continue
			}

			dependencyType := "direct"

			if pkg.Indirect {
				dependencyType = "indirect"
			}

			_, err = conn.Exec(
				ctx,
				`
            INSERT INTO dependencies
            (
                artifact_id,
                name,
                version,
                dependency_type
            )
            VALUES ($1, $2, $3, $4)
            `,
				artifactID,
				pkg.Name,
				pkg.Version,
				dependencyType,
			)

			if err != nil {
				fmt.Println("Failed to store dependency:", err)
				return
			}

			fmt.Println(
				"Stored dependency:",
				pkg.Name,
				pkg.Version,
				dependencyType,
			)
		}
	}
	if err != nil {
		fmt.Println("Failed to parse Trivy JSON:", err)
		return
	}

	vulnerabilityCount := 0

	for _, result := range report.Results {
		vulnerabilityCount += len(result.Vulnerabilities)
	}

	fmt.Println("Vulnerabilities found:", vulnerabilityCount)

	scanStatus := "CLEAN"

	if vulnerabilityCount > 0 {
		scanStatus = "VULNERABLE"
	}

	fmt.Println("Scan status:", scanStatus)

	// Store scan result in PostgreSQL
	var scanID int64

	err = conn.QueryRow(
		ctx,
		`
    INSERT INTO scan_results
    (
        artifact_id,
        scanner,
        scan_status,
        findings_count
    )
    VALUES ($1, $2, $3, $4)
    RETURNING scan_id
    `,
		artifactID,
		"trivy",
		scanStatus,
		vulnerabilityCount,
	).Scan(&scanID)

	if err != nil {
		fmt.Println("Failed to store scan result:", err)
		return
	}

	fmt.Println("Scan ID:", scanID)
	fmt.Println("Scan result stored in PostgreSQL")

	for _, result := range report.Results {

		for _, vulnerability := range result.Vulnerabilities {

			_, err = conn.Exec(
				ctx,
				`
            INSERT INTO vulnerabilities
            (
                scan_id,
                library,
                cve_id,
                severity,
                installed_version,
                fixed_version,
                title
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            `,
				scanID,
				vulnerability.PkgName,
				vulnerability.VulnerabilityID,
				vulnerability.Severity,
				vulnerability.InstalledVersion,
				vulnerability.FixedVersion,
				vulnerability.Title,
			)

			if err != nil {
				fmt.Println("Failed to store vulnerability:", err)
				return
			}

			fmt.Println(
				"Stored vulnerability:",
				vulnerability.VulnerabilityID,
				vulnerability.Severity,
			)
		}
	}

	// Update artifact status
	_, err = conn.Exec(
		ctx,
		`
        UPDATE artifacts
        SET status = $1
        WHERE artifact_id = $2
        `,
		scanStatus,
		artifactID,
	)

	if err != nil {
		fmt.Println("Failed to update artifact status:", err)
		return
	}

	fmt.Println("Artifact status updated to:", scanStatus)
}
