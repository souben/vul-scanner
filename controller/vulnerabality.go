package controller

import (
	"context"
	"net/http"
	"souben/kai/repo"
	"souben/kai/service"

	"github.com/gin-gonic/gin"
)

// Scan handles the POST /scan endpoint
func Scan(c *gin.Context) {
	var reqBody repo.ScanRequestBody

	// Parse the request body
	if err := c.BindJSON(&reqBody); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format: " + err.Error()})
		return
    }

	// Validate the request
	if reqBody.Repo == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Repository name is required"})
		return
	}

	// Call the service to scan the repository
	results, err := service.Scan(reqBody.Repo, reqBody.Files)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Scan failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, results)
}

// Query handles the endpoint /query 
func Query(c *gin.Context){
	// Define a body struct to store the request body
	var body repo.QueryBody
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Query Failed: "+ err.Error()})
		return
	}	

	if body.Filters.Severity == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Severity must be a valid non-empty string"})
		return
	}

	ctx := context.Background()

	// Now, Let's fetch the vulnerabilities based on the severity filter
	vulnerabilities, err := service.Filter(ctx, body.Filters.Severity)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusAccepted, vulnerabilities)
}