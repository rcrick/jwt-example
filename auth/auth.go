package auth

import (
	"errors"
	"fmt"
	"github.com/go-redis/redis/v7"
	"time"
)

type AuthInterface interface {
	CreateAuth(string, *TokenDetails) error
	FetchAuth(string) (string, error)
	DeleteRefresh(string) error
	DeleteTokens(*AccessDetails) error
}

type service struct {
	client *redis.Client
}

var _ AuthInterface = &service{}

func NewAuth(client *redis.Client) *service {
	return &service{client: client}
}

func (s *service) CreateAuth(userId string, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()
	atCreated, err := s.client.Set(td.AccessUuid, userId, at.Sub(now)).Result()
	if err != nil {
		return err
	}

	rtCreated, err := s.client.Set(td.RefreshUuid, userId, rt.Sub(now)).Result()
	if err != nil {
		return err
	}
	if atCreated == "0" || rtCreated == "0" {
		return errors.New("no record inserted")
	}
	return nil
}

func (s *service) FetchAuth(tokenUuid string) (string, error) {
	userId, err := s.client.Get(tokenUuid).Result()
	if err != nil {
		return "", err
	}

	return userId, nil
}

func (s *service) DeleteTokens(authD *AccessDetails) error {
	refreshUuid := fmt.Sprintf("%s++%s", authD.TokenUuid, authD.UserId)
	existErr, err := s.client.Exists(authD.TokenUuid, refreshUuid).Result()
	if existErr != 2 {
		return err
	}
	deleteAt, err := s.client.Del(authD.TokenUuid).Result()
	if err != nil {
		return err
	}
	deleteRt, err := s.client.Del(refreshUuid).Result()
	if err != nil {
		return err
	}
	if deleteAt != 1 || deleteRt != 1 {
		return errors.New("something went wrong")
	}

	return nil
}

func (s *service) DeleteRefresh(refreshUuid string) error {
	deleted, err := s.client.Del(refreshUuid).Result()
	if err != nil {
		return err
	}
	if deleted == 0 {
		return errors.New("DeleteRefresh failed")
	}
	return nil
}
