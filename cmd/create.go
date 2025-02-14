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
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
)

var errorsCreatingChecksumFiles []error
var resultsCreatingChecksumFiles []ChecksumFileCreationResult

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create checksum files.",
	Long: `Generate the checksum of the files and store them in checksum files with the extension .sha512.

Example:
  checksum-utils create .
  checksum-utils create ./work
	checksum-utils create ~/documents
  checksum-utils create /mnt/external-disk/budget.pdf
`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		printHeader()

		for _, path := range args {
			argFileInfo, err := os.Stat(path)
			if err != nil {
				errorsCreatingChecksumFiles = append(errorsCreatingChecksumFiles, err)
				continue
			}

			fmt.Println()
			fmt.Println("Processing", path)

			resultsCreatingChecksumFiles = []ChecksumFileCreationResult{}

			if argFileInfo.IsDir() {
				directoryAbsolutePath, err := filepath.Abs(path)
				if err != nil {
					errorsCreatingChecksumFiles = append(errorsCreatingChecksumFiles, err)
					return
				}

				if err := filepath.Walk(directoryAbsolutePath, func(filePath string, fileInfo os.FileInfo, err error) error {
					if err != nil {
						errorsCreatingChecksumFiles = append(errorsCreatingChecksumFiles, err)
						fmt.Println("Error: ", err)
						return err
					}

					if fileInfo.IsDir() {
						return nil
					}

					return handleChecksumFileCreation(filePath, &resultsCreatingChecksumFiles)
				}); err != nil {
					errorsCreatingChecksumFiles = append(errorsCreatingChecksumFiles, err)
					fmt.Println("Error: ", err)
				}
			} else {
				fileAbsolutePath, err := filepath.Abs(path)
				if err != nil {
					errorsCreatingChecksumFiles = append(errorsCreatingChecksumFiles, err)
					continue
				}

				ext := filepath.Ext(fileAbsolutePath)
				if ext == ".sha512" {
					isChecksumFileError := errors.New(fileAbsolutePath + " is a checksum file.")
					errorsCreatingChecksumFiles = append(errorsCreatingChecksumFiles, isChecksumFileError)
					continue
				}

				handleChecksumFileCreation(path, &resultsCreatingChecksumFiles)
			}

			printResultsCreatingChecksumFiles(resultsCreatingChecksumFiles)
		}

		printErrorsCreatingChecksumFiles()
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c

		fmt.Println()
		printResultsCreatingChecksumFiles(resultsCreatingChecksumFiles)
		printErrorsCreatingChecksumFiles()

		os.Exit(1)
	}()
}

type ChecksumFileCreationStatus string

const (
	Created  ChecksumFileCreationStatus = "Created"
	Existing ChecksumFileCreationStatus = "Existing"
	Failed   ChecksumFileCreationStatus = "Failed"
)

type ChecksumFileCreationResult struct {
	Path   string
	Status ChecksumFileCreationStatus
	Error  error
}

func handleChecksumFileCreation(filePath string, results *[]ChecksumFileCreationResult) error {
	fileAbsolutePath, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}

	ext := filepath.Ext(fileAbsolutePath)
	if ext == ".sha512" {
		return nil
	}

	fmt.Print("- ", fileAbsolutePath)

	result := createChecksumFile(fileAbsolutePath)

	*results = append(*results, result)

	switch result.Status {
	case Created:
		fmt.Print(" ✅")
	case Existing:
		fmt.Print(" ⏭️")
	case Failed:
		fmt.Print(" ❌")
	}

	fmt.Println()

	return nil
}

func createChecksumFile(fileAbsolutePath string) ChecksumFileCreationResult {
	file, err := os.Open(fileAbsolutePath)
	if err != nil {
		return ChecksumFileCreationResult{Path: fileAbsolutePath, Status: Failed, Error: err}
	}

	defer file.Close()

	// Checksum file
	if _, err := os.Stat(fileAbsolutePath + ".sha512"); err == nil {
		return ChecksumFileCreationResult{Path: fileAbsolutePath, Status: Existing, Error: nil}
	} else if errors.Is(err, os.ErrNotExist) {
		// Create a new SHA512 hash object
		hash := sha512.New()

		// Copy the file content to the hash object
		if _, err := io.Copy(hash, file); err != nil {
			return ChecksumFileCreationResult{Path: fileAbsolutePath, Status: Failed, Error: err}
		}

		// Get the checksum as a byte slice
		fileChecksum := hash.Sum(nil)

		// Convert the checksum to a hexadecimal string
		hexFileChecksum := hex.EncodeToString(fileChecksum)

		// Create checksum file
		checksumFile, err := os.Create(fileAbsolutePath + ".sha512")
		if err != nil {
			return ChecksumFileCreationResult{Path: fileAbsolutePath, Status: Failed, Error: err}
		}

		defer checksumFile.Close()

		// Write the file checksum on the checksum file
		if _, err := checksumFile.WriteString(hexFileChecksum); err != nil {
			return ChecksumFileCreationResult{Path: fileAbsolutePath, Status: Failed, Error: err}
		}

		return ChecksumFileCreationResult{Path: fileAbsolutePath, Status: Created, Error: nil}
	} else {
		return ChecksumFileCreationResult{Path: fileAbsolutePath, Status: Failed, Error: err}
	}
}

func printResultsCreatingChecksumFiles(results []ChecksumFileCreationResult) {
	if len(results) > 0 {
		fmt.Println("Results:", len(results), "files processed")
	}

	var createdChecksumFilesQuantity = 0
	var existingChecksumFilesQuantity = 0
	var failedResults []ChecksumFileCreationResult

	for _, result := range results {
		switch result.Status {
		case Created:
			createdChecksumFilesQuantity++
		case Existing:
			existingChecksumFilesQuantity++
		case Failed:
			failedResults = append(failedResults, result)
		}
	}

	if createdChecksumFilesQuantity > 0 {
		fmt.Println("- ✅ | ", createdChecksumFilesQuantity, "checksum files created successfully")
	}

	if existingChecksumFilesQuantity > 0 {
		fmt.Println("- ⏭️  | ", existingChecksumFilesQuantity, "files already have an existing checksum file")
	}

	if len(failedResults) > 0 {
		fmt.Println("- ❌ | ", len(failedResults), "checksum files failed to create")
		fmt.Println("Fails")
		for _, failedResult := range failedResults {
			fmt.Print("- ", failedResult.Path, " | Error: ", failedResult.Error)
			fmt.Println()
		}
	}
}

func printErrorsCreatingChecksumFiles() {
	if len(errorsCreatingChecksumFiles) > 0 {
		fmt.Println()
		fmt.Println("Errors:")

		for _, error := range errorsCreatingChecksumFiles {
			fmt.Println("- ", error)
		}
	}
}
