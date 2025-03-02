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
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var (
	version = "v0.0.10"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "checksum-utils",
	Version: version,
	Short:   "Multiplatform checksum utils.",
	Long: `A multiplatform checksum utils for NAS admins.
`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println()

		printResultsCheckingChecksumFiles(resultsCheckingChecksumFiles)
		printErrorsCheckingChecksumFiles()

		printResultsCreatingChecksumFiles(resultsCreatingChecksumFiles)
		printErrorsCreatingChecksumFiles()

		os.Exit(1)
	}()
}

func printHeader() {
	fmt.Println("Checksum-Utils", version)
	fmt.Println("https://github.com/JMOrbegoso/checksum-utils")
}
