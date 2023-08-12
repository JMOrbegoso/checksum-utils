BINARY_NAME=checksum-utils

build:
	mkdir -p ./out
	GOARCH=amd64 GOOS=linux go build -o ./out/${BINARY_NAME} .
	GOARCH=amd64 GOOS=windows go build -o ./out/${BINARY_NAME}.exe .

clean:
	go clean
	rm -rf ./out
