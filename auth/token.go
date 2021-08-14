package auth

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
	"net/http"
	"os"
	"strings"
	"time"
)

type TokenDetails struct {
	AccessUuid   string
	RefreshUuid  string
	AccessToken  string
	RefreshToken string
	AtExpires    int64
	RtExpires    int64
}

type AccessDetails struct {
	TokenUuid string
	UserId    string
}

type TokenInterface interface {
	CreateToken(userID string) (*TokenDetails, error)
	ExtractTokenMetadata(r *http.Request) (*AccessDetails, error)
}

type tokenService struct{}

var _ TokenInterface = &tokenService{}

func NewToken() *tokenService {
	return &tokenService{}
}
func (t *tokenService) CreateToken(userID string) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AccessUuid = uuid.NewV4().String()
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()

	td.RefreshUuid = td.AccessUuid + "++" + userID
	td.RtExpires = time.Now().Add(time.Hour * 1).Unix()

	var err error
	atClaims := jwt.MapClaims{}
	atClaims["user_id"] = userID
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["exp"] = td.AtExpires
	aToken := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = aToken.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}

	rtClaims := jwt.MapClaims{}
	rtClaims["user_id"] = userID
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["exp"] = td.RtExpires
	rToken := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rToken.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}

	return td, nil
}

func getToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}

	return ""
}

func verifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := getToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (t *tokenService) ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := verifyToken(r)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		userId, userOk := claims["user_id"].(string)
		if !ok || !userOk {
			return nil, errors.New("unauthorized")
		}
		return &AccessDetails{
			TokenUuid: accessUuid,
			UserId:    userId,
		}, nil
	}
	return nil, errors.New("something went wrong")
}

func TokenValid(r *http.Request) error {
	token, err := verifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}