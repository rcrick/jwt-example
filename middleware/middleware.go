package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/rcrick/jwt-example.git/handler"
	"net/http"
)

func TokenAuthMiddleware(handler handler.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		metadata, err := handler.Token.ExtractTokenMetadata(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			c.Abort()
			return
		}
		_, err = handler.Auth.FetchAuth(metadata.TokenUuid)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			c.Abort()
			return
		}
		c.Next()
	}
}
