package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/download", func(c *gin.Context) {
		// Same dependency, but the filename is a constant: no request data reaches FileAttachment.
		c.FileAttachment("report.pdf", "report.pdf")
	})
	_ = r.Run()
}
