.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


# TODO: run check versus this makefile alias. It should work without errors
.PHONY: install
install: ## Installs all dependencies that are needed for the development process
	echo "don't forget to install npm if it is not installed on your machine"
	echo "don't forget to install python3-pip if it is not installed on your machine"
	echo "Installing instruments for developing..."

	echo "Installing redoc-cli" && sudo npm install -g redoc-cli
	echo "Installing pre-commit and pre-commit hooks" && sudo apt-get update && sudo apt-get -y install pre-commit && \
																				pre-commit install-hooks
	echo "Installing dependencies from go.mod..." && go mod download -modcacherw
	echo "Installing oapi-codegen" && go install github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen@latest
	echo "Creating .env file..." && cp .env.example .env
	echo "Set up hosts..." && grep -qxF '127.0.0.1 mongo1' /etc/hosts || (printf '\n# gofundament:\n127.0.0.1 mongo1' | sudo tee -a /etc/hosts) && \
							  grep -qxF '127.0.0.1 mongo2' /etc/hosts || (printf '\n127.0.0.1 mongo2' | sudo tee -a /etc/hosts)


.PHONY: run_app_simple
run_app_simple: ## Runs app, redis and mongo1 mongo2 in docker environment
	docker compose up --build mongo1 mongo2 redis app


.PHONY: run_app_full
run_app_full: ## Runs full version of app including swagger and nginx
	docker compose up -d --build mongo1 mongo2 redis app swagger nginx


# TODO: run check versus this makefile alias. It should work without errors
.PHONY: linters_loc
linters_loc:  ## Runs linters locally
	pre-commit run --all-files
	echo 'hadolint:'
	docker run --rm -i hadolint/hadolint < Dockerfile


.PHONY: run_test_env
run_test_env:  ## Runs test environment for application in foreground for local testing
	docker compose up --build mongo1 mongo2 redis


.PHONY: run_tests_in_docker
run_tests_in_docker:  ## Runs redis and db cluster in docker environment. Then runs tests in docker environment as well.
	docker compose up -d --build mongo1 mongo2 redis
	docker compose build tests_only
	docker compose run --rm tests_only go test -p 1 -count=3 -race ./...


.PHONY: gen
gen:  ## Generates go types from spec and RSA key pairs for JWT auth
	oapi-codegen -old-config-style -generate "types," -package rest ./docs/openapi.yml > app/common/rest/types.go

	mkdir secrets -p

	openssl genrsa -out ./secrets/auth-access-private.pem 2048
	openssl rsa -in ./secrets/auth-access-private.pem -outform PEM -pubout -out ./secrets/auth-access-public.pem

	openssl genrsa -out ./secrets/auth-refresh-private.pem 2048
	openssl rsa -in ./secrets/auth-refresh-private.pem -outform PEM -pubout -out ./secrets/auth-refresh-public.pem


.PHONY: down
down:  ## Alias for docker compose down
	docker compose down


.PHONY: clean_up_compose
clean_up_compose:  ## Removes volumes & orphans
	docker compose down --volumes -t 0 --remove-orphans
