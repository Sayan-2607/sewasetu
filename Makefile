run:   ; go run .
test:  ; go vet ./... && go test -count=1 -v ./...
build: ; CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o sewasetu .
linux: ; GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o sewasetu-linux-amd64 .
