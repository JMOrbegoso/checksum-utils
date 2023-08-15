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
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check files checksum.",
	Long: `Get the content of the checksum files and compare them with the checksum of their no-checksum files.

Example:
	checksum-utils check ~/documents
	checksum-utils check /mnt/external-disk/documents
`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var errorsArray []error

		for _, arg := range args {
			var filesQuantity = 0
			var matchesQuantity = 0
			var unmatchesQuantity = 0
			var invalidsQuantity = 0
			var noChecksumFileQuantity = 0

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
				log.Println("Recursively checking checksum files of", fileFullPath)
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

					checksumFileResult := checkChecksumFile(fileFullPath)
					filesQuantity++

					switch checksumFileResult {
					case Match:
						matchesQuantity++
						log.Println(fileFullPath, "✅")
					case NotFound:
						noChecksumFileQuantity++
						log.Println(fileFullPath, "👻")
					case Invalid:
						invalidsQuantity++
						log.Println(fileFullPath, "🗑️")
					case NotMatch:
						unmatchesQuantity++
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
				log.Println("Checking checksum file of", fileFullPath)
				log.Println()

				checksumFileResult := checkChecksumFile(fileFullPath)
				filesQuantity++

				switch checksumFileResult {
				case Match:
					matchesQuantity++
					log.Println(fileFullPath, "✅")
				case NotFound:
					noChecksumFileQuantity++
					log.Println(fileFullPath, "👻")
				case Invalid:
					invalidsQuantity++
					log.Println(fileFullPath, "🗑️")
				case NotMatch:
					unmatchesQuantity++
					log.Println(fileFullPath, "❌")
				}
			}

			log.Println()
			if noChecksumFileQuantity > 0 {
				log.Println("      👻      | ", noChecksumFileQuantity, "files without a checksum file")
			}
			if invalidsQuantity > 0 {
				log.Println("      🗑️      | ", invalidsQuantity, "checksum files with invalid format")
			}
			if matchesQuantity > 0 {
				log.Println("      ✅      | ", matchesQuantity, "checksum files match")
			}
			if unmatchesQuantity > 0 {
				log.Println("      ❌      | ", unmatchesQuantity, "checksum files not match")
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
	rootCmd.AddCommand(checkCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// checkCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// checkCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

type ChecksumFileResult string

const (
	Match    ChecksumFileResult = "Match"
	NotFound ChecksumFileResult = "NotFound"
	Invalid  ChecksumFileResult = "Invalid"
	NotMatch ChecksumFileResult = "NotMatch"
)

func checkChecksumFile(fileFullPath string) ChecksumFileResult {
	file, err := os.Open(fileFullPath)
	if err != nil {
		panic(err)
	}

	defer file.Close()

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

	// Checksum file
	if _, err := os.Stat(fileFullPath + ".sha512"); err != nil {
		return NotFound
	}

	checksumFileContentByteArray, err := os.ReadFile(fileFullPath + ".sha512")
	if err != nil {
		panic(err)
	}

	checksumFileContentString := string(checksumFileContentByteArray)

	if len(checksumFileContentString) != 128 {
		return Invalid
	}

	if strings.EqualFold(hexFileChecksum, checksumFileContentString) {
		return Match
	} else {
		return NotMatch
	}
}
