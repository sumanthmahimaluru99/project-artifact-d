package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	minioEndpoint  = "localhost:9000"
	minioAccessKey = "minioadmin"
	minioSecretKey = "minioadmin"
	bucketName     = "artifacts"
)

var minioClient *minio.Client

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Project Artifact API is healthy")
}

func artifactUploadHandler(w http.ResponseWriter, r *http.Request) {

	var sequenceNumber int64

	err := postgresConn.QueryRow(
		context.Background(),
		"SELECT nextval('artifact_id_seq')",
	).Scan(&sequenceNumber)

	if err != nil {
		http.Error(w, "Failed to generate artifact ID", http.StatusInternalServerError)
		fmt.Println("Artifact ID generation error:", err)
		return
	}

	artifactID := fmt.Sprintf("ART-%d", sequenceNumber)

	fmt.Println("Generated Artifact ID:", artifactID)

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	err = r.ParseMultipartForm(20 << 20)
	if err != nil {
		http.Error(w, "Failed to parse upload", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fileData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read artifact", http.StatusInternalServerError)
		return
	}

	hash := sha256.Sum256(fileData)
	sha256Hash := fmt.Sprintf("%x", hash)

	fmt.Println("SHA-256:", sha256Hash)
	fmt.Println("Artifact received:")
	fmt.Println("Name:", header.Filename)

	filename := header.Filename

	baseName := strings.TrimSuffix(filename, ".tar.gz")

	parts := strings.Split(baseName, "-")

	version := parts[len(parts)-1]

	fmt.Println("Detected version:", version)

	objectKey := artifactID + "/" + header.Filename

	_, err = minioClient.PutObject(
		context.Background(),
		bucketName,
		objectKey,
		bytes.NewReader(fileData),
		int64(len(fileData)),
		minio.PutObjectOptions{
			ContentType: "application/octet-stream",
		},
	)

	if err != nil {
		http.Error(w, "Failed to store artifact", http.StatusInternalServerError)
		fmt.Println("MinIO upload error:", err)
		return
	}

	fmt.Println("Artifact stored in MinIO:")
	fmt.Println("Bucket:", bucketName)
	fmt.Println("Object:", objectKey)

	result, err := postgresConn.Exec(
		context.Background(),
		`
    INSERT INTO artifacts (
    artifact_id,
    name,
    version,
    sha256,
    storage_bucket,
    storage_key,
    status
)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    `,
		artifactID,
		header.Filename,
		version,
		sha256Hash,
		bucketName,
		objectKey,
		"RECEIVED",
	)

	if err != nil {
		http.Error(w, "Failed to save artifact metadata", http.StatusInternalServerError)
		fmt.Println("PostgreSQL insert error:", err)
		return
	}

	fmt.Println("PostgreSQL rows affected:", result.RowsAffected())

	fmt.Println("Artifact metadata saved in PostgreSQL")

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(
		w,
		"Artifact stored successfully: %s\n",
		objectKey,
	)
}

func generateArtifactID() string {
	return "ART-1001"
}

func main() {

	postgresConn = connectPostgres()

	if postgresConn == nil {
		return
	}

	defer postgresConn.Close(context.Background())

	var err error

	minioClient, err = minio.New(
		minioEndpoint,
		&minio.Options{
			Creds:  credentials.NewStaticV4(minioAccessKey, minioSecretKey, ""),
			Secure: false,
		},
	)

	if err != nil {
		fmt.Println("Failed to create MinIO client:", err)
		return
	}

	fmt.Println("Connected to MinIO")

	http.HandleFunc("/health", healthHandler)

	http.HandleFunc(
		"/api/v1/artifacts",
		artifactUploadHandler,
	)

	fmt.Println("Project Artifact API started on port 8080")

	err = http.ListenAndServe(":8080", nil)

	if err != nil {
		fmt.Println("Server failed:", err)
	}
}
