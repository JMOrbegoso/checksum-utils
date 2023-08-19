BINARY_NAME=checksum-utils

build:
	mkdir -p ./out
	GOARCH=amd64 GOOS=darwin go build -o ./out/${BINARY_NAME}_darwin-amd64 .
	GOARCH=arm64 GOOS=darwin go build -o ./out/${BINARY_NAME}_darwin-arm64 .
	GOARCH=amd64 GOOS=linux go build -o ./out/${BINARY_NAME}_linux-amd64 .
	GOARCH=arm64 GOOS=linux go build -o ./out/${BINARY_NAME}_linux-arm64 .
	GOARCH=amd64 GOOS=windows go build -o ./out/${BINARY_NAME}_windows-amd64.exe .
	GOARCH=arm64 GOOS=windows go build -o ./out/${BINARY_NAME}_windows-arm64.exe .

	sha256sum ./out/${BINARY_NAME}_darwin-amd64  | sed 's, .*/,  ,' >> ./out/${BINARY_NAME}_checksums.txt
	sha256sum ./out/${BINARY_NAME}_darwin-arm64  | sed 's, .*/,  ,' >> ./out/${BINARY_NAME}_checksums.txt
	sha256sum ./out/${BINARY_NAME}_linux-amd64  | sed 's, .*/,  ,' >> ./out/${BINARY_NAME}_checksums.txt
	sha256sum ./out/${BINARY_NAME}_linux-arm64  | sed 's, .*/,  ,' >> ./out/${BINARY_NAME}_checksums.txt
	sha256sum ./out/${BINARY_NAME}_windows-amd64.exe  | sed 's, .*/,  ,' >> ./out/${BINARY_NAME}_checksums.txt
	sha256sum ./out/${BINARY_NAME}_windows-arm64.exe  | sed 's, .*/,  ,' >> ./out/${BINARY_NAME}_checksums.txt

clean:
	go clean
	rm -rf ./out
