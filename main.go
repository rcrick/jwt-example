package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v7"
	"github.com/joho/godotenv"
	"github.com/rcrick/jwt-example.git/auth"
	"github.com/rcrick/jwt-example.git/handler"
	"github.com/rcrick/jwt-example.git/middleware"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("load env faild: %v", err)
	}
}

func NewRedisDB(host, port, passwod string) *redis.Client {
	return redis.NewClient(&redis.Options{Addr: host + ":" + port})
}
func main() {
	appAddr := ":" + os.Getenv("PORT")

	redisClient := NewRedisDB(os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT"), os.Getenv("REDIS_PASSWORD"))

	a := auth.NewAuth(redisClient)
	t := auth.NewToken()

	service := handler.Handler{a, t}

	router := gin.Default()

	router.POST("/login", service.Login)
	router.POST("/todo", middleware.TokenAuthMiddleware(), service.CreateTodo)
	router.POST("/logout", middleware.TokenAuthMiddleware(), service.Logout)
	router.POST("/refresh", service.Refresh)

	srv := &http.Server{
		Addr:    appAddr,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	//Wait for interrupt signal to gracefully shutdown the server with a timeout of 10 seconds
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	log.Println("Server exiting")

}
