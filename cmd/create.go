/*
Copyright © 2023 JM Orbegoso

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
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create checksum files.",
	Long: `Generate the checksum of the files and store them in checksum files with the extension .sha512.

Example:
  checksum-utils create ~/documents
  checksum-utils create /mnt/external-disk/documents
`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("No arguments.")
			os.Exit(1)
		}

		var errorsArray []error

		for _, arg := range args {
			var filesQuantity = 0
			var createdsQuantity = 0
			var existentValidsQuantity = 0
			var existentInvalidsQuantity = 0
			var errorsCreatingQuantity = 0

			fileInfo, err := os.Stat(arg)
			if err != nil {
				errorsArray = append(errorsArray, err)
				continue
			}

			if fileInfo.IsDir() {
				fileFullPath, err := filepath.Abs(arg)
				if err != nil {
					panic(err)
				}

				log.Println("----------------------------------------------------------------------------------------------------")
				log.Println("Recursively creating checksum files of", fileFullPath)
				log.Println()

				if err := filepath.Walk(arg, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}

					fileFullPath, err := filepath.Abs(path)
					if err != nil {
						panic(err)
					}

					if info.IsDir() {
						log.Println(fileFullPath)
						return nil
					}

					if strings.HasSuffix(fileFullPath, ".sha512") {
						return nil
					}

					checksumFileCreationResult := createChecksumFile(fileFullPath)
					filesQuantity++

					switch checksumFileCreationResult {
					case Created:
						createdsQuantity++
						log.Println(fileFullPath, "✅")
					case ExistentValid:
						existentValidsQuantity++
						log.Println(fileFullPath, "⏭️")
					case ExistentInvalid:
						existentInvalidsQuantity++
						log.Println(fileFullPath, "🗑️")
					case ErrorCreating:
						errorsCreatingQuantity++
						log.Println(fileFullPath, "❌")
					}

					return nil
				}); err != nil {
					log.Println(err)
				}
			} else {
				fileFullPath, err := filepath.Abs(arg)
				if err != nil {
					panic(err)
				}

				if strings.HasSuffix(fileFullPath, ".sha512") {
					myError := errors.New(fileFullPath + " is a checksum file.")
					errorsArray = append(errorsArray, myError)
					continue
				}

				log.Println("----------------------------------------------------------------------------------------------------")
				log.Println("Creating checksum file of", fileFullPath)
				log.Println()

				checksumFileCreationResult := createChecksumFile(fileFullPath)
				filesQuantity++

				switch checksumFileCreationResult {
				case Created:
					createdsQuantity++
					log.Println(fileFullPath, "✅")
				case ExistentValid:
					existentValidsQuantity++
					log.Println(fileFullPath, "⏭️")
				case ExistentInvalid:
					existentInvalidsQuantity++
					log.Println(fileFullPath, "🗑️")
				case ErrorCreating:
					errorsCreatingQuantity++
					log.Println(fileFullPath, "❌")
				}
			}

			log.Println()
			if createdsQuantity > 0 {
				log.Println("      ✅      | ", createdsQuantity, "created checksum files")
			}
			if existentValidsQuantity > 0 {
				log.Println("      ⏭️      | ", existentValidsQuantity, "already existent valid checksum files")
			}
			if existentInvalidsQuantity > 0 {
				log.Println("      🗑️      | ", existentInvalidsQuantity, "already existent invalid checksum files")
			}
			if errorsCreatingQuantity > 0 {
				log.Println("      ❌      | ", errorsCreatingQuantity, "error creating checksum files")
			}
			if filesQuantity > 0 {
				log.Println("     Total    | ", filesQuantity, "files")
			}
			log.Println("----------------------------------------------------------------------------------------------------")

			println("")
		}

		for _, error := range errorsArray {
			log.Println(error)
			println()
		}
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

type ChecksumFileCreationResult string

const (
	Created         ChecksumFileCreationResult = "Created"
	ExistentValid   ChecksumFileCreationResult = "ExistentValid"
	ExistentInvalid ChecksumFileCreationResult = "ExistentInvalid"
	ErrorCreating   ChecksumFileCreationResult = "ErrorCreating"
)

func createChecksumFile(fileFullPath string) ChecksumFileCreationResult {
	file, err := os.Open(fileFullPath)
	if err != nil {
		panic(err)
	}

	defer file.Close()

	// Checksum file
	if _, err := os.Stat(fileFullPath + ".sha512"); err != nil {
		// Create a new SHA512 hash object
		hash := sha512.New()

		// Copy the file content to the hash object
		if _, err := io.Copy(hash, file); err != nil {
			panic(err)
		}

		// Get the checksum as a byte slice
		fileChecksum := hash.Sum(nil)

		// Convert the checksum to a hexadecimal string
		hexFileChecksum := hex.EncodeToString(fileChecksum)

		// Create checksum file
		checksumFile, err := os.Create(fileFullPath + ".sha512")
		if err != nil {
			return ErrorCreating
		}

		defer checksumFile.Close()

		// Write the file checksum on the checksum file
		if _, err := checksumFile.WriteString(hexFileChecksum); err != nil {
			return ErrorCreating
		}

		return Created
	} else {
		checksumFileContentByteArray, err := os.ReadFile(fileFullPath + ".sha512")
		if err != nil {
			panic(err)
		}

		checksumFileContentString := string(checksumFileContentByteArray)

		if len(checksumFileContentString) != 128 {
			return ExistentInvalid
		} else {
			return ExistentValid
		}
	}
}
