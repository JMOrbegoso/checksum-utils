BINARY_NAME=checksum-utils

build:
	mkdir -p ./out
	GOARCH=amd64 GOOS=linux go build -o ./out/${BINARY_NAME}_linux-amd64 .
	GOARCH=amd64 GOOS=windows go build -o ./out/${BINARY_NAME}_windows-amd64.exe .

clean:
	go clean
	rm -rf ./out
