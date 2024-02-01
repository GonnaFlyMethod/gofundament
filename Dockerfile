# TODO: Create separated dockerfile for production needs:
# 1) Build container should not include dev dependencies such as python, linters, git etc.
# 2) Distroless container should be used for running bin of app
# 3) Remove docs container
# 4) Double check that the docker user is rootless in the container with app

FROM golang:1.20 AS tests_only
WORKDIR /go/src/build

COPY go.mod go.sum ./
RUN go mod download

COPY app ./app

FROM tests_only AS dev

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-pip && \
    rm /usr/lib/python3.11/EXTERNALLY-MANAGED && \
    pip3 install --no-cache-dir pre-commit==2.16.0

RUN git init

COPY .pre-commit-config.yaml .golangci.yml Dockerfile ./

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o app_binary app/main.go && \
  pre-commit install-hooks && pre-commit run --all-files

# hadolint ignore=DL3006
FROM gcr.io/distroless/base AS app

WORKDIR /app

COPY --from=dev /go/src/build/app_binary .
COPY secrets .

ENTRYPOINT ["./app_binary"]

FROM swaggerapi/swagger-ui:v4.15.5 AS docs
COPY ./docs/openapi.yml /openapi.yml
