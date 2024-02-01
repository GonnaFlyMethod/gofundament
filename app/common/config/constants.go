package config

const (
	AppDomain = "APP_DOMAIN"

	SMTPHost             = "SMTP_HOST"
	SMTPPort             = "SMTP_PORT"
	TechEmail            = "TECH_EMAIL"
	PasswordForTechEmail = "PASSWORD_FOR_TECH_EMAIL"

	DBUser     = "DB_USER"
	DBPassword = "DB_PASSWORD"
	DBHost     = "DB_HOST"
	DBPort     = "DB_PORT"
	DBName     = "DB_NAME"

	InMemoryStorageHost     = "IN_MEMORY_STORAGE_HOST"
	InMemoryStoragePort     = "IN_MEMORY_STORAGE_PORT"
	InMemoryStoragePassword = "IN_MEMORY_STORAGE_PASSWORD" //nolint:gosec
)
