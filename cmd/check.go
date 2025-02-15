/*
Copyright © 2025 JM Orbegoso

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var errorsCheckingChecksumFiles []error
var resultsCheckingChecksumFiles []ChecksumFileVerificationResult

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check files checksum.",
	Long: `Get the content of the checksum files and compare them with the checksum of their no-checksum files.
Example:
  checksum-utils check .
  checksum-utils check ./work
	checksum-utils check ~/documents
  checksum-utils check /mnt/external-disk/budget.pdf
`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		printHeader()

		for _, path := range args {
			argFileInfo, err := os.Stat(path)
			if err != nil {
				errorsCheckingChecksumFiles = append(errorsCheckingChecksumFiles, err)
				continue
			}

			fmt.Println()
			fmt.Println("Processing", path)

			resultsCheckingChecksumFiles = []ChecksumFileVerificationResult{}

			if argFileInfo.IsDir() {
				directoryAbsolutePath, err := filepath.Abs(path)
				if err != nil {
					errorsCheckingChecksumFiles = append(errorsCheckingChecksumFiles, err)
					return
				}

				if err := filepath.Walk(directoryAbsolutePath, func(filePath string, fileInfo os.FileInfo, err error) error {
					if err != nil {
						errorsCheckingChecksumFiles = append(errorsCheckingChecksumFiles, err)
						fmt.Println("Error: ", err)
						return err
					}

					if fileInfo.IsDir() {
						return nil
					}

					return handleChecksumFileVerification(filePath, &resultsCheckingChecksumFiles)
				}); err != nil {
					errorsCheckingChecksumFiles = append(errorsCheckingChecksumFiles, err)
					fmt.Println("Error: ", err)
				}
			} else {
				fileAbsolutePath, err := filepath.Abs(path)
				if err != nil {
					errorsCheckingChecksumFiles = append(errorsCheckingChecksumFiles, err)
					continue
				}

				ext := filepath.Ext(fileAbsolutePath)
				if ext == ".sha512" {
					isChecksumFileError := errors.New(fileAbsolutePath + " is a checksum file.")
					errorsCheckingChecksumFiles = append(errorsCheckingChecksumFiles, isChecksumFileError)
					continue
				}

				handleChecksumFileVerification(path, &resultsCheckingChecksumFiles)
			}

			printResultsCheckingChecksumFiles(resultsCheckingChecksumFiles)
		}

		printErrorsCheckingChecksumFiles()
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}

type ChecksumFileVerificationStatus string

const (
	Match          ChecksumFileVerificationStatus = "Match"
	NotMatch       ChecksumFileVerificationStatus = "NotMatch"
	NotFound       ChecksumFileVerificationStatus = "NotFound"
	CheckingFailed ChecksumFileVerificationStatus = "CheckingFailed"
)

type ChecksumFileVerificationResult struct {
	Path   string
	Status ChecksumFileVerificationStatus
	Error  error
}

func handleChecksumFileVerification(filePath string, results *[]ChecksumFileVerificationResult) error {
	fileAbsolutePath, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}

	ext := filepath.Ext(fileAbsolutePath)
	if ext == ".sha512" {
		return nil
	}

	fmt.Print("- ", fileAbsolutePath)

	result := checkChecksumFile(fileAbsolutePath)

	*results = append(*results, result)

	switch result.Status {
	case Match:
		fmt.Print(" ✅")
	case NotMatch:
		fmt.Print(" ❌")
	case NotFound:
		fmt.Print(" 👻")
	case CheckingFailed:
		fmt.Print(" ❌")
	}

	fmt.Println()

	return nil
}

func checkChecksumFile(fileAbsolutePath string) ChecksumFileVerificationResult {
	file, err := os.Open(fileAbsolutePath)
	if err != nil {
		return ChecksumFileVerificationResult{Path: fileAbsolutePath, Status: CheckingFailed, Error: err}
	}

	if _, err := os.Stat(fileAbsolutePath + ".sha512"); err != nil {
		return ChecksumFileVerificationResult{Path: fileAbsolutePath, Status: NotFound, Error: nil}
	}

	defer file.Close()

	// Create a new SHA512 hash object
	hash := sha512.New()

	// Copy the file content to the hash object
	if _, err := io.Copy(hash, file); err != nil {
		return ChecksumFileVerificationResult{Path: fileAbsolutePath, Status: CheckingFailed, Error: err}
	}

	// Get the checksum as a byte slice
	fileChecksum := hash.Sum(nil)

	// Convert the checksum to a hexadecimal string
	hexFileChecksum := hex.EncodeToString(fileChecksum)

	checksumFileContentByteArray, err := os.ReadFile(fileAbsolutePath + ".sha512")
	if err != nil {
		return ChecksumFileVerificationResult{Path: fileAbsolutePath, Status: CheckingFailed, Error: err}
	}

	checksumFileContentString := string(checksumFileContentByteArray)

	if strings.EqualFold(hexFileChecksum, checksumFileContentString) {
		return ChecksumFileVerificationResult{Path: fileAbsolutePath, Status: Match, Error: nil}
	}

	return ChecksumFileVerificationResult{Path: fileAbsolutePath, Status: NotMatch, Error: nil}
}

func printResultsCheckingChecksumFiles(results []ChecksumFileVerificationResult) {
	if len(results) > 0 {
		fmt.Println("Results:", len(results), "files processed")
	}

	var matchedChecksumFilesQuantity = 0
	var notMatchedChecksumFilesQuantity = 0
	var notExistingChecksumFilesQuantity = 0
	var failedResults []ChecksumFileVerificationResult

	for _, result := range results {
		switch result.Status {
		case Match:
			matchedChecksumFilesQuantity++
		case NotMatch:
			notMatchedChecksumFilesQuantity++
		case NotFound:
			notExistingChecksumFilesQuantity++
		case CheckingFailed:
			failedResults = append(failedResults, result)
		}
	}

	if matchedChecksumFilesQuantity > 0 {
		fmt.Println("- ✅ | ", matchedChecksumFilesQuantity, "checksum files match")
	}

	if notMatchedChecksumFilesQuantity > 0 {
		fmt.Println("- ❌ | ", notMatchedChecksumFilesQuantity, "checksum files not match")
	}

	if notExistingChecksumFilesQuantity > 0 {
		fmt.Println("- 👻  | ", notExistingChecksumFilesQuantity, "files without a checksum file")
	}

	if len(failedResults) > 0 {
		fmt.Println("- ❌ | ", len(failedResults), "checksum files failed to check")
		fmt.Println("Fails")
		for _, failedResult := range failedResults {
			fmt.Print("- ", failedResult.Path, " | Error: ", failedResult.Error)
			fmt.Println()
		}
	}
}

func printErrorsCheckingChecksumFiles() {
	if len(errorsCheckingChecksumFiles) > 0 {
		fmt.Println()
		fmt.Println("Errors:")

		for _, error := range errorsCheckingChecksumFiles {
			fmt.Println("- ", error)
		}
	}
}
