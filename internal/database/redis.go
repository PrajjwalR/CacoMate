package database

import (
	"context"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
	"github.com/shridarpatil/whatomate/internal/config"
	"github.com/zerodha/logf"
)

func NewRedis(cfg *config.RedisConfig, log logf.Logger) (*redis.Client, error) {
	redisURL := os.Getenv("REDIS_URL")
	var client *redis.Client

	if redisURL != "" {
		log.Info("initializing redis connection using REDIS_URL environment variable")
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Error("failed to parse REDIS_URL", "error", err)
			return nil, fmt.Errorf("failed to parse REDIS_URL: %w", err)
		}
		client = redis.NewClient(opt)
	} else {
		log.Info("initializing redis connection using config values")
		client = redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Password: cfg.Password,
			DB:       cfg.DB,
		})
	}

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		log.Error("failed to connect to redis. please ensure redis is running locally", "error", err)
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return client, nil
}
