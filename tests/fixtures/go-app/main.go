package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/download", func(c *gin.Context) {
		// Request-supplied filename reaches FileAttachment: the vulnerable call.
		c.FileAttachment("report.pdf", c.Query("name"))
	})
	_ = r.Run()
}
