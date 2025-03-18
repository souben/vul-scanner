package main

import (
	"log"
	"os"
	"souben/kai/controller"
	"souben/kai/service"

	"github.com/gin-gonic/gin"
)

func main() {

	// Initialize the database
	if err := service.InitDatabase(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer service.CloseDatabase()

	// Set up Gin router
	r := gin.Default()

	// Define routes
	r.POST("/scan", controller.Scan)
	r.POST("/query", controller.Query)

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start the server
	log.Printf("Starting server on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
