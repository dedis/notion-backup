// Package main implements a utility tool to archive a notion block and save it
// in an encrypted form. It also offers the mean to decrypt an encrypted file.
//
// The archives are save as ".zip.aes" files, with their correcsponding
// ".zip.iv" input vectors needed for decryption. The filename uses the hash of
// the block id and the timedate.
//
// Archive request example:
//   go run mod.go -id BLOCK_ID -token NOTION_TOKEN_V2 \\
//                 -key 64_HEX_KEY -path EXPORT_FOLDER_PATH
//
// The decrypt function will expect a *.iv file next to the encrypted file.
//
// Decrypt example:
//   go run mod.go -decrypt -path /tmp/xxx.zip.aes -key 64_HEX_KEY
//
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dedis/notion-backup/types"

	"golang.org/x/xerrors"
)

const (
	baseURL    = "https://www.notion.so/api/v3/"
	exportURI  = "enqueueTask"
	getTaskURI = "getTasks"
)

var printer io.Writer = os.Stdout

func main() {

	var blockID string
	var token string
	var keyStr string
	var path string
	var isDecrypt bool

	flag.StringVar(&blockID, "id", "", "block id")
	flag.StringVar(&token, "token", "", "V2 token")
	flag.StringVar(&keyStr, "key", "", "aes key in hex format (64 hex = 32 bytes)")
	flag.StringVar(&path, "path", os.TempDir(), "folder to save file, or file to decrypt")

	flag.BoolVar(&isDecrypt, "decrypt", false, "will decrypt the file")

	flag.Parse()

	key, err := hex.DecodeString(keyStr)
	if err != nil {
		log.Fatalf("failed to decode hex key: %v", err)
	}

	if isDecrypt {
		if path == "" || keyStr == "" {
			fmt.Fprintln(printer, "for decrypt please provide -path= and -key=")
			return
		}
		err = decrypt(path, key)
		if err != nil {
			log.Fatalf("failed to decrypt: %v", err)
		}

		return
	}

	if blockID == "" || token == "" || keyStr == "" || path == "" {
		fmt.Fprintln(printer, "please provide -ID=, -token=, -path=, and -key= parameters")
		return
	}

	fmt.Fprintf(printer, "sending request to export block '%s'\n", blockID)
	res, err := sendExportRequest(blockID, token)
	if err != nil {
		log.Fatalf("failed to send export request: %v", err)
	}

	fmt.Fprintf(printer, "request sent, created task '%s'\n", res.TaskID)

	for {
		fmt.Fprint(printer, "getting task status...")
		taskResp, err := getTask(res.TaskID, token)
		if err != nil {
			log.Fatalf("failed to get task '%s': %v", res.TaskID, err)
		}

		if len(taskResp.Results) == 0 {
			log.Fatal("no response")
		}

		pagesExported := taskResp.Results[0].Status.PagesExported
		fmt.Fprintln(printer, "exported", pagesExported, "pages")

		if taskResp.Results[0].State == "in_progress" {
			time.Sleep(time.Second * 5)
		} else if taskResp.Results[0].State == "success" {
			fmt.Fprintln(printer, "Done!")

			hash := sha256.New()
			hash.Write([]byte(blockID))
			blockIDHash := hash.Sum(nil)
			prefix := hex.EncodeToString(blockIDHash)

			fileName := prefix + "-" + time.Now().Format("2006-01-02-150405") + ".zip"
			sourceURL := taskResp.Results[0].Status.ExportURL

			err = downloadFile(sourceURL, filepath.Join(path, fileName), key)
			if err != nil {
				log.Fatalf("failed to download file: %v", err)
			}

			break
		} else {
			fmt.Fprintln(printer, "unknown state:", taskResp.Results[0].State)
			break
		}
	}
}

// sendExportRequest sends a request to the Notion API to export the selected
// block and all its subcomponents. This request returns a task that we can poll
// to follow the progress.
func sendExportRequest(blockID, token string) (*types.ExportResp, error) {
	exportReq := types.ExportRequest{
		Task: types.Task{
			EventName: "exportBlock",
			Request: types.Request{
				BlockID: blockID,
				ExportOptions: types.ExportOptions{
					ExportType: "markdown",
					Locale:     "en",
					TimeZone:   "Europe/Zurich",
				},
				Recursive: true,
			},
		},
	}

	buf, err := json.Marshal(&exportReq)
	if err != nil {
		return nil, xerrors.Errorf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+exportURI, bytes.NewBuffer(buf))
	if err != nil {
		return nil, xerrors.Errorf("failed to create http request: %v", err)
	}

	req.Header.Add("content-type", "application/json")
	req.Header.Add("cookie", "token_v2="+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("expected code 200, got %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("failed to read body: %v", err)
	}

	var res types.ExportResp
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal response: %v", err)
	}

	return &res, nil
}

// getTask sends a request to the Notion API to get a task.
func getTask(taskID string, token string) (*types.TaskResp, error) {
	taskRequest := types.TaskRequest{
		TaskIds: []string{taskID},
	}

	buf, err := json.Marshal(&taskRequest)
	if err != nil {
		return nil, xerrors.Errorf("failed to marshal task request: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, baseURL+getTaskURI, bytes.NewBuffer(buf))
	if err != nil {
		return nil, xerrors.Errorf("failed to create http request: %v", err)
	}

	httpReq.Header.Add("content-type", "application/json")
	httpReq.Header.Add("cookie", "token_v2="+token)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, xerrors.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("expected code 200, got %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("failed to read body: %v", err)
	}

	var res types.TaskResp
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal response: %v", err)
	}

	return &res, nil
}

// downloadFile downloads the file at the source URL, saves it to the given path
// encrypted with the given key. Uses a stream cipher.
func downloadFile(sourceURL, path string, key []byte) error {
	path = path + ".aes"

	block, err := aes.NewCipher(key)
	if err != nil {
		return xerrors.Errorf("failed to create cipher: %v", err)
	}

	iv := make([]byte, block.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return xerrors.Errorf("failed to create random IV: %v", err)
	}

	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)

	// For security reasons, lets not print the URL, as anyone can use it
	// fmt.Fprintln(printer, "downloading from", sourceURL)

	resp, err := http.Get(sourceURL)
	if err != nil {
		return xerrors.Errorf("failed to get source URL: %v", err)
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		return xerrors.Errorf("failed to create path: %v", err)
	}
	defer out.Close()

	fmt.Fprintln(printer, "copying and encrypting to", path, ", this may take a while...")
	tot := 0

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			// Write into file
			out.Write(buf[:n])
			tot += n
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}

	// save the IV
	err = ioutil.WriteFile(path+".iv", iv, os.ModePerm)
	if err != nil {
		return xerrors.Errorf("failed to write IV file: %v", err)
	}

	fmt.Fprintf(printer, "copied %d bytes to '%s'\n", tot, path)

	return nil
}

// decrypt decrypts the file at the provided path with the given key. It expects
// the input vector IV to be saved next to the file with .iv extension. The new
// file will have its .aes extension removed if present, or the .txt appended.
func decrypt(path string, key []byte) error {
	encrypted, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("failed to open encrypted file: %v", err)
	}
	defer encrypted.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return xerrors.Errorf("failed to create cipher: %v", err)
	}

	ivfile, err := os.Open(path + ".iv")
	iv, err := ioutil.ReadAll(ivfile)
	if err != nil {
		xerrors.Errorf("failed to read IV '%s': %v", path+".iv", err)
	}

	var decryptedPath string
	if strings.HasSuffix(path, ".aes") {
		decryptedPath = strings.TrimSuffix(path, ".aes")
	} else {
		decryptedPath = path + ".txt"
	}

	decrypted, err := os.OpenFile(decryptedPath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return xerrors.Errorf("failed to open decrypted file: %v", err)
	}
	defer decrypted.Close()

	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
	for {
		n, err := encrypted.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			decrypted.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("after %d, failed to read bytes: %v", n, err)
		}
	}

	fmt.Fprintln(printer, "file decrypted at"+decryptedPath)

	return nil
}
