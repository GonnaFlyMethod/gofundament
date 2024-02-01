package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type Config struct {
	AppConfig       AppConfig
	SMTP            SMTPConfig
	Database        DatabaseConfig
	InMemoryStorage InMemoryStorageConfig
}

type AppConfig struct {
	Domain string
}

type SMTPConfig struct {
	Host string
	Port string

	Email    string
	Password string
}

type DatabaseConfig struct {
	User     string
	Password string

	Host         string
	Port         string
	DatabaseName string
}

type InMemoryStorageConfig struct {
	Host     string
	Port     string
	Password string
}

func (dbc DatabaseConfig) ConnectionString() string {
	// TODO: authSource should be changed

	return fmt.Sprintf(
		"mongodb://%s:%s@%s/%s?authSource=admin",
		dbc.User, dbc.Password,
		net.JoinHostPort(dbc.Host, dbc.Port),
		dbc.DatabaseName,
	)
}

func BuildFromEnv() Config {
	return Config{
		AppConfig: AppConfig{
			Domain: os.Getenv(AppDomain),
		},

		SMTP: SMTPConfig{
			Host:     os.Getenv(SMTPHost),
			Port:     os.Getenv(SMTPPort),
			Email:    os.Getenv(TechEmail),
			Password: os.Getenv(PasswordForTechEmail),
		},

		Database: DatabaseConfig{
			DatabaseName: os.Getenv(DBName),
			User:         os.Getenv(DBUser),
			Password:     os.Getenv(DBPassword),
			Host:         os.Getenv(DBHost),
			Port:         os.Getenv(DBPort),
		},

		InMemoryStorage: InMemoryStorageConfig{
			Host:     os.Getenv(InMemoryStorageHost),
			Port:     os.Getenv(InMemoryStoragePort),
			Password: os.Getenv(InMemoryStoragePassword),
		},
	}
}

var ErrEmptyEnvVar = errors.New("empty environment variable")

func CheckEnvironmentVars() error {
	requiredEnvVars := []string{
		AppDomain,

		SMTPHost,
		SMTPPort,
		TechEmail,
		PasswordForTechEmail,

		DBUser,
		DBPassword,
		DBHost,
		DBPort,
		DBName,

		InMemoryStorageHost,
		InMemoryStoragePort,
		InMemoryStoragePassword,
	}

	var emptyEnvs []string

	for _, envVarKey := range requiredEnvVars {
		if value := os.Getenv(envVarKey); value == "" {
			emptyEnvs = append(emptyEnvs, envVarKey)
		}
	}

	if len(emptyEnvs) > 0 {
		return errors.Wrapf(
			ErrEmptyEnvVar,
			"empty environment variables: %s",
			strings.Join(emptyEnvs, ", "),
		)
	}

	return nil
}
