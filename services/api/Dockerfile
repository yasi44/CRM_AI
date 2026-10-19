# ---- build stage -----------------------------------------------------------
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
# `go mod tidy` resolves go.sum on first build. In your own repo, commit go.sum
# and replace this line with `RUN go mod download` for reproducible builds.
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /crm-api .

# ---- runtime stage: distroless = no shell, no package manager, tiny attack surface
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /crm-api /crm-api
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD ["/crm-api","healthcheck"]
ENTRYPOINT ["/crm-api"]
CMD ["serve"]
