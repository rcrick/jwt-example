package handler

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/rcrick/jwt-example.git/auth"
	"net/http"
	"os"
)

type Handler struct {
	Auth  auth.AuthInterface
	Token auth.TokenInterface
}

func NewHandler(auth auth.AuthInterface, token auth.TokenInterface) *Handler {
	return &Handler{Auth: auth, Token: token}
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var user = User{
	ID:       "1",
	Username: "username",
	Password: "password",
}

type TODO struct {
	UserID string `json:"id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
}

func (h *Handler) Login(c *gin.Context) {
	var u User
	if err := c.Bind(&u); err != nil {
		if u.Username == "" || u.Password == "" {
			c.JSON(http.StatusBadRequest, "Invalid params")
			return
		}
	}
	if u.Username != user.Username || u.Password != user.Password {
		c.JSON(http.StatusUnauthorized, "username or password invalid")
		return
	}
	td, err := h.Token.CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	err = h.Auth.CreateAuth(user.ID, td)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	tokens := map[string]string{
		"access_token":  td.AccessToken,
		"refresh_token": td.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

func (h *Handler) Logout(c *gin.Context) {
	metadata, err := h.Token.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	if metadata != nil {
		err := h.Auth.DeleteTokens(metadata)
		if err != nil {
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
	}
	c.JSON(http.StatusOK, "Successfully logged out")
	return
}

func (h *Handler) CreateTodo(c *gin.Context) {
	var td TODO
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusBadRequest, "invalid json")
		return
	}
	metadata, err := h.Token.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	userId, err := h.Auth.FetchAuth(metadata.TokenUuid)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	td.UserID = userId

	c.JSON(http.StatusCreated, td)
}

func (h *Handler) Refresh(c *gin.Context) {
	tokenMap := map[string]string{}
	if err := c.ShouldBindJSON(&tokenMap); err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}

	refreshToken := tokenMap["refresh_token"]

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})

	//os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf")

	if err != nil {
		c.JSON(http.StatusUnauthorized, "Refresh token expired")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusUnauthorized, "refresh expired")
		return
	} else {
		refreshUuid, ok := claims["refresh_uuid"].(string)
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, err)
			return
		}
		userId, ok := claims["user_id"].(string)
		if !ok {
			c.JSON(http.StatusUnprocessableEntity, err)
			return
		}
		err := h.Auth.DeleteRefresh(refreshUuid)
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			return
		}

		td, err := h.Token.CreateToken(userId)
		if err != nil {
			c.JSON(http.StatusForbidden, err.Error())
			return
		}
		saveErr := h.Auth.CreateAuth(userId, td)
		if saveErr != nil {
			c.JSON(http.StatusForbidden, saveErr.Error())
			return
		}
		tokens := map[string]string{
			"access_token":  td.AccessToken,
			"refresh_token": td.RefreshToken,
		}
		c.JSON(http.StatusCreated, tokens)
	}
}
