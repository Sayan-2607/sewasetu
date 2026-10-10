# Build:  docker build -t sewasetu .
# Run:    docker run -p 8080:8080 -e PUBLIC_BASE_URL=https://your.domain -e ADMIN_PASSWORD=change-me -v sewasetu-data:/data sewasetu
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /sewasetu .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /sewasetu /sewasetu
ENV DATA_DIR=/data PORT=8080 DEMO_INBOX=off
EXPOSE 8080
ENTRYPOINT ["/sewasetu"]
