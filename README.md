<h1 align="center">Checksum-Utils ✅</h1>
<h2 align="center">Multiplatform file checksum tools</h2>

<br/>

<p align="center">
    <img src="https://img.shields.io/badge/Go-informational?style=flat&logo=go&logoColor=white" alt="Go badge"/>
</p>

Checksum Utils is a CLI tool to manage the checksum of your files, focused on NAS systems.

## ✨ Features

- [Create checksum files](#create-checksum-files)
- [Check checksum files](#check-checksum-files)

## 💻 Install

1. Download the latest release from the [releases page](https://github.com/JMOrbegoso/checksum-utils/releases/latest) according to your operating system.

2. Move and rename the downloaded executable to your PATH, so you can use it from anywhere.

   ```bash
   mv ./checksum-utils_linux-amd64 /usr/local/bin/checksum-utils
   ```

3. Give it execute permissions if necessary:

   ```bash
   chmod 0755 /usr/local/bin/checksum-utils
   ```

## 🚀 Usage

### Create checksum files

This command reads the files in a folder, gets their checksums, and creates a file with the .sha512 extension with it, so you can have a record of the checksum of that file.

Let's say you want to create the checksum files for your folder "documents":

```tree
├── ~
│   ├── documents
│   │   ├── document-1.pdf
│   │   ├── document-2.ppt
│   │   └── document-3.csv
│   ├── music
│   ├── pictures
│   └── videos
```

Use the command:

```bash
checksum-utils create ~/documents
```

This command will create a .sha512 checksum file for each file in your folder:

```tree
├── ~
│   ├── documents
│   │   ├── document-1.pdf
│   │   ├── document-1.pdf.sha512 <-- created by checksum-utils
│   │   │
│   │   ├── document-2.ppt
│   │   ├── document-2.ppt.sha512 <-- created by checksum-utils
│   │   │
│   │   ├── document-3.csv
│   │   └── document-3.csv.sha512 <-- created by checksum-utils
│   ├── music
│   ├── pictures
│   └── videos
```

### Check checksum files

This command reads the content of the files generated by the command "checksum-utils create ~/documents" and compares them with the original file to verify if the checksum remains the same.

Let's say you want to check the checksums of the files of your folder "documents":

```tree
├── ~
│   ├── documents
│   │   ├── document-1.pdf
│   │   ├── document-1.pdf.sha512
│   │   │
│   │   ├── document-2.ppt
│   │   ├── document-2.ppt.sha512
│   │   │
│   │   ├── document-3.csv
│   │   └── document-3.csv.sha512
│   ├── music
│   ├── pictures
│   └── videos
```

Use the command:

```bash
checksum-utils check ~/documents
```

The command will display the results of the comparation of the current checksum of the file with the one stored in the file with the .sha512 extension:

```tree
├── ~
│   ├── documents
│   │   ├── document-1.pdf ✅
│   │   │
│   │   ├── document-2.ppt ✅
│   │   │
│   │   └── document-3.csv ❌
│   ├── music
│   ├── pictures
│   └── videos
```

## 🏗️ Dev

You must have [golang](https://go.dev/doc/install) installed on your system.

1. Clone the project:

   ```bash
   git clone https://github.com/JMOrbegoso/checksum-utils.git
   ```

2. Install Go dependencies:

   ```bash
   go mod download
   ```

3. Build:

   ```bash
   make build
   ```

## 🧑‍💻 Author

**JMOrbegoso:**

- Website: [www.jmorbegoso.dev](https://www.jmorbegoso.dev)
- Blog: [blog.jmorbegoso.dev](https://blog.jmorbegoso.dev)
- Github: [@JMOrbegoso](https://github.com/JMOrbegoso/)
- LinkedIn: [@jmorbegosodev](https://www.linkedin.com/in/jmorbegosodev/)
