package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var postgresConn *pgx.Conn

func connectPostgres() *pgx.Conn {
	conn, err := pgx.Connect(
		context.Background(),
		"postgres://artifact:artifactpass@localhost:5432/artifactdb",
	)

	if err != nil {
		fmt.Println("Failed to connect to PostgreSQL:", err)
		return nil
	}

	fmt.Println("Connected to PostgreSQL")

	return conn
}
