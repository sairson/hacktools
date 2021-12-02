package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	cmap "github.com/orcaman/concurrent-map"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type mainConfig struct {
	token      string
	parallel   int
	interval   int
	prefix     string
	debugMode  bool
	singleMode bool
	version    bool
	keepMode   bool
	authCode   string
	blockSize  int
	hashCheck  bool
	passCode   string
	silentMode bool
	validDays  int
}

type uploadResult struct {
	Hash string `json:"hash"`
	Key  string `json:"key"`
}

type initResp struct {
	Token        string
	TransferGUID string
	FileGUID     string
	EncodeID     string
	Exp          int64  `json:"expireAt"`
	ID           string `json:"uploadId"`
}

type upResp struct {
	Etag string `json:"etag"`
	MD5  string `json:"md5"`
}

type prepareSendResp struct {
	UploadToken  string `json:"uptoken"`
	TransferGUID string `json:"transferguid"`
	FileGUID     string `json:"fileguid"`
	UniqueURL    string `json:"uniqueurl"`
	Prefix       string `json:"prefix"`
	QRCode       string `json:"qrcode"`
	Error        bool   `json:"error"`
	ErrorMessage string `json:"error_message"`
}

type slek struct {
	ETag string `json:"etag"`
	Part int64  `json:"partNumber"`
}

type clds struct {
	Parts    []slek `json:"parts"`
	FName    string `json:"fname"`
	Mimetype string `json:"mimeType"`
	Metadata map[string]string
	Vars     map[string]string
}

type beforeSendResp struct {
	FileGuid string `json:"fileGuid"`
}

type finishResponse struct {
	TempDownloadCode string `json:"tempDownloadCode"`
	Status           bool   `json:"complete"`
}

var (
	runConfig = new(mainConfig)
	commands  [][]string
)

type uploadPart struct {
	content []byte
	count   int64
}

func init() {
	addFlag(&runConfig.authCode, []string{"auth", "a"}, "", "Your auth code (optional)")
	addFlag(&runConfig.token, []string{"cookie", "c"}, "", "Your User cookie (optional)")
	addFlag(&runConfig.parallel, []string{"parallel", "p"}, 3, "Parallel task count (default 3)")
	addFlag(&runConfig.blockSize, []string{"block", "b"}, 1200000, "Upload Block Size (default 1200000)")
	addFlag(&runConfig.interval, []string{"timeout", "t"}, 15, "Request retry/timeout limit (in second, default 10)")
	addFlag(&runConfig.prefix, []string{"prefix", "o"}, ".", "File download dictionary/name (default \".\")")
	addFlag(&runConfig.singleMode, []string{"single", "s"}, false, "Single Upload Mode")
	addFlag(&runConfig.hashCheck, []string{"hash"}, false, "Check Hash after block upload (might slower)")
	addFlag(&runConfig.passCode, []string{"password"}, "", "Set password")
	addFlag(&runConfig.validDays, []string{"valid"}, 1, "Valid Days (default 1)")
	flag.Parse()
}

func main() {
	files := flag.Args()

	if len(files) == 0 {
		fmt.Printf("missing file(s) or url(s)\n")
		return
	}

	if runConfig.blockSize > 4194304 {
		runConfig.blockSize = 524288
	}

	var f []string
	for _, v := range files {
		var err error
		if strings.HasPrefix(v, "https://") {
			// Download Mode
		} else {
			f = append(f, v)
		}
		if err != nil {
			fmt.Printf("Error: %v", err)
		}
	}

	if len(f) != 0 {
		upload(f)
	}


}


func addFlag(p interface{}, cmd []string, val interface{}, usage string) {
	c := fmt.Sprintf(" --%s", cmd[0])
	if len(cmd) > 1 {
		c += fmt.Sprintf(", -%s", cmd[1])
	}

	s := []string{c, "", usage}
	ptr := unsafe.Pointer(reflect.ValueOf(p).Pointer())
	for _, item := range cmd {
		switch val := val.(type) {
		case int:
			s[1] = "int"
			flag.IntVar((*int)(ptr), item, val, usage)
		case string:
			s[1] = "string"
			flag.StringVar((*string)(ptr), item, val, usage)
		case bool:
			flag.BoolVar((*bool)(ptr), item, val, usage)
		}
	}
	commands = append(commands, s)
}


const (
	prepareSend    = "https://cowtransfer.com/api/transfer/preparesend"
	setPassword    = "https://cowtransfer.com/api/transfer/v2/bindpasscode"
	beforeUpload   = "https://cowtransfer.com/api/transfer/beforeupload"
	uploadFinish   = "https://cowtransfer.com/api/transfer/uploaded"
	uploadComplete = "https://cowtransfer.com/api/transfer/complete"
	initUpload     = "https://upload-fog-cn-east-1.qiniup.com/buckets/cowtransfer-yz/objects/%s/uploads"
	doUpload       = "https://upload-fog-cn-east-1.qiniup.com/buckets/cowtransfer-yz/objects/%s/uploads/%s/%d"
	finUpload      = "https://upload-fog-cn-east-1.qiniup.com/buckets/cowtransfer-yz/objects/%s/uploads/%s"

	// block = 1024 * 1024
)

type uploadConfig struct {
	wg      *sync.WaitGroup
	config  *initResp
	hashMap *cmap.ConcurrentMap
}

func upload(files []string) {
	if !runConfig.singleMode {
		for _, v := range files {
			if isExist(v) {
				err := filepath.Walk(v, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						fmt.Printf("filapath walker returns error: %v, onfile: %s", err, path)
						return nil
					}
					if info.IsDir() {
						return nil
					}
					config, err := getSendConfig(info.Size())
					if err != nil {
						fmt.Printf("getSendConfig returns error: %v, onfile: %s", err, path)
						return nil
					}
					// 输出下载目的地址
					fmt.Printf("Destination: %s\n", config.UniqueURL)
					err = _upload(path, config)
					if err != nil {
						fmt.Printf("upload returns error: %v, onfile: %s", err, path)
					}
					err = completeUpload(config)
					if err != nil {
						fmt.Printf("complete upload returns error: %v, onfile: %s", err, path)
					}
					return nil
				})
				if err != nil {
					fmt.Printf("filepath.walk returns error: %v, onfile: %s", err, v)
				}
			} else {
				fmt.Printf("%s not found\n", v)
			}
		}

		return
	}
	totalSize := int64(0)

	for _, v := range files {
		if isExist(v) {
			err := filepath.Walk(v, func(path string, info os.FileInfo, err error) error {
				if info.IsDir() {
					return nil
				}
				totalSize += info.Size()
				return nil
			})
			if err != nil {
				fmt.Printf("filepath.walk returns error: %v, onfile: %s\n", err, v)
			}
		} else {
			fmt.Printf("%s not found\n", v)
		}
	}

	config, err := getSendConfig(totalSize)
	if err != nil {
		fmt.Printf("getSendConfig(single mode) returns error: %v\n", err)
	}
	fmt.Printf("Destination: %s\n", config.UniqueURL)
	for _, v := range files {
		if isExist(v) {
			err = filepath.Walk(v, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					fmt.Printf("filapath walker returns error: %v, onfile: %s", err, path)
					return nil
				}
				if info.IsDir() {
					return nil
				}
				err = _upload(path, config)
				if err != nil {
					fmt.Printf("upload returns error: %v, onfile: %s\n", err, path)
				}
				return nil
			})
			if err != nil {
				fmt.Printf("filepath.walk(upload) returns error: %v, onfile: %s\n", err, v)
			}
		} else {
			fmt.Printf("%s not found\n", v)
		}
	}
	err = completeUpload(config)
	if err != nil {
		fmt.Printf("complete upload(single mode) returns error: %v\n", err)
	}
}

func _upload(v string, baseConf *prepareSendResp) error {
	fmt.Printf("Local: %s\n", v)

	info, err := getFileInfo(v)
	if err != nil {
		return fmt.Errorf("getFileInfo returns error: %v", err)
	}

	config, err := getUploadConfig(info, baseConf)

	if err != nil {
		return fmt.Errorf("getUploadConfig returns error: %v", err)
	}
	file, err := os.Open(v)
	if err != nil {
		return fmt.Errorf("openFile returns error: %v", err)
	}

	wg := new(sync.WaitGroup)
	ch := make(chan *uploadPart)
	hashMap := cmap.New()
	for i := 0; i < runConfig.parallel; i++ {
		//go uploader(&ch, wg, bar, config.UploadToken, &hashMap)
		go uploader(&ch, uploadConfig{
			wg:      wg,
			config:  config,
			hashMap: &hashMap,
		})
	}
	part := int64(0)
	for {
		part++
		buf := make([]byte, runConfig.blockSize)
		nr, err := file.Read(buf)
		if nr <= 0 || err != nil {
			break
		}
		if nr > 0 {
			wg.Add(1)
			ch <- &uploadPart{
				content: buf[:nr],
				count:   part,
			}
		}
	}

	wg.Wait()
	close(ch)
	_ = file.Close()
	// finish upload
	err = finishUpload(config, info, &hashMap, part)
	if err != nil {
		return fmt.Errorf("finishUpload returns error: %v", err)
	}
	return nil
}

func uploader(ch *chan *uploadPart, conf uploadConfig) {
	for item := range *ch {
	Start:
		postURL := fmt.Sprintf(doUpload, conf.config.EncodeID, conf.config.ID, item.count)


		//blockPut
		ticket, err := blockPut(postURL, item.content, conf.config.Token)
		if err != nil {

			goto Start
		}
		conf.hashMap.Set(strconv.FormatInt(item.count, 10), ticket)
		conf.wg.Done()
	}

}

func blockPut(postURL string, buf []byte, token string) (string, error) {
	data := new(bytes.Buffer)
	data.Write(buf)
	body, err := newRequest(postURL, data, token, "PUT")
	if err != nil {

		return "", err
	}
	var rBody upResp
	if err := json.Unmarshal(body, &rBody); err != nil {

		return "", err
	}
	if runConfig.hashCheck {
		if hashBlock(buf) != rBody.MD5 {

			return "", fmt.Errorf("block hashcheck failed")
		}

	}
	return rBody.Etag, nil
}

func hashBlock(buf []byte) string {
	return fmt.Sprintf("%x", md5.Sum(buf))
}

func urlSafeEncode(enc string) string {
	r := base64.StdEncoding.EncodeToString([]byte(enc))
	r = strings.ReplaceAll(r, "+", "-")
	r = strings.ReplaceAll(r, "/", "_")
	return r
}

func finishUpload(config *initResp, info os.FileInfo, hashMap *cmap.ConcurrentMap, limit int64) error {

	mergeFileURL := fmt.Sprintf(finUpload, config.EncodeID, config.ID)
	var postData clds
	for i := int64(1); i <= limit; i++ {
		item, alimasu := hashMap.Get(strconv.FormatInt(i, 10))
		if alimasu {
			postData.Parts = append(postData.Parts, slek{
				ETag: item.(string),
				Part: i,
			})
		}
	}
	postData.FName = info.Name()
	postBody, err := json.Marshal(postData)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(postBody)
	resp, err := newRequest(mergeFileURL, reader, config.Token, "POST")
	if err != nil {
		return err
	}

	// read returns
	var mergeResp *uploadResult
	if err = json.Unmarshal(resp, &mergeResp); err != nil {
		return err
	}


	data := map[string]string{
		"transferGuid": config.TransferGUID,
		"fileGuid":     config.FileGUID,
		"hash":         mergeResp.Hash,
	}
	body, err := newMultipartRequest(uploadFinish, data, 0)
	if err != nil {
		return err
	}
	if string(body) != "true" {
		return fmt.Errorf("finish upload failed: status != true")
	}
	return nil
}

func completeUpload(config *prepareSendResp) error {
	data := map[string]string{"transferGuid": config.TransferGUID, "fileId": ""}

	body, err := newMultipartRequest(uploadComplete, data, 0)
	if err != nil {
		return err
	}
	var rBody finishResponse
	if err := json.Unmarshal(body, &rBody); err != nil {
		return fmt.Errorf("read finish resp failed: %s", err)
	}
	if !rBody.Status {
		return fmt.Errorf("finish upload failed: complete is not true")
	}
	fmt.Printf("Short Download Code: %s\n", rBody.TempDownloadCode)
	return nil
}

func getSendConfig(totalSize int64) (*prepareSendResp, error) {
	data := map[string]string{
		"validDays": strconv.Itoa(runConfig.validDays),
		"totalSize": strconv.FormatInt(totalSize, 10),
	}
	body, err := newMultipartRequest(prepareSend, data, 0)
	if err != nil {
		return nil, err
	}
	config := new(prepareSendResp)
	err = json.Unmarshal(body, &config)
	if err != nil {
		return nil, err
	}
	if config.Error {
		return nil, fmt.Errorf(config.ErrorMessage)
	}
	if runConfig.passCode != "" {
		// set password
		data := map[string]string{
			"transferguid": config.TransferGUID,
			"passcode":     runConfig.passCode,
		}
		body, err = newMultipartRequest(setPassword, data, 0)
		if err != nil {
			return nil, err
		}
		if string(body) != "true" {
			return nil, fmt.Errorf("set password unsuccessful")
		}
	}
	return config, nil
}

func getUploadConfig(info os.FileInfo, config *prepareSendResp) (*initResp, error) {



	data := map[string]string{
		"fileId":        "",
		"type":          "",
		"fileName":      info.Name(),
		"originalName":  info.Name(),
		"fileSize":      strconv.FormatInt(info.Size(), 10),
		"transferGuid":  config.TransferGUID,
		"storagePrefix": config.Prefix,
	}
	resp, err := newMultipartRequest(beforeUpload, data, 0)
	if err != nil {
		return nil, err
	}
	var beforeResp *beforeSendResp
	if err = json.Unmarshal(resp, &beforeResp); err != nil {
		return nil, err
	}
	config.FileGUID = beforeResp.FileGuid

	data = map[string]string{
		"transferGuid":  config.TransferGUID,
		"storagePrefix": config.Prefix,
	}
	p, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	w := urlSafeEncode(fmt.Sprintf("%s/%s/%s", config.Prefix, config.TransferGUID, info.Name()))
	inits := fmt.Sprintf(initUpload, w)

	resp, err = newRequest(inits, bytes.NewReader(p), config.UploadToken, "POST")
	if err != nil {
		return nil, err
	}
	var initResp *initResp
	if err = json.Unmarshal(resp, &initResp); err != nil {
		return nil, err
	}

	initResp.Token = config.UploadToken
	initResp.EncodeID = w
	initResp.TransferGUID = config.TransferGUID
	initResp.FileGUID = config.FileGUID

	// return config, nil
	return initResp, nil
}

func newRequest(link string, postBody io.Reader, upToken string, action string) ([]byte, error) {

	client := http.Client{Timeout: time.Duration(runConfig.interval) * time.Second}
	req, err := http.NewRequest(action, link, postBody)
	if err != nil {

		return nil, err
	}
	req.Header.Set("referer", "https://cowtransfer.com/")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "UpToken "+upToken)

	resp, err := client.Do(req)
	if err != nil {

		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()

	return body, nil
}

func getFileInfo(path string) (os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func addHeaders(req *http.Request) *http.Request {
	req.Header.Set("Referer", "https://cowtransfer.com/")
	req.Header.Set("User-Agent", "Chrome/80.0.3987.149 CowTransfer-Uploader")
	req.Header.Set("Origin", "https://cowtransfer.com/")
	req.Header.Set("Cookie", fmt.Sprintf("%scf-cs-k-20181214=%d;", req.Header.Get("Cookie"), time.Now().UnixNano()))
	return req
}

func addTk(req *http.Request) {
	ck := runConfig.token
	if runConfig.authCode != "" {
		ck = fmt.Sprintf("%s; cow-auth-token=%s", runConfig.token, runConfig.authCode)
	}

	req.Header.Set("cookie", ck)
	req.Header.Set("authorization", runConfig.authCode)
}

func newMultipartRequest(url string, params map[string]string, retry int) ([]byte, error) {

	client := http.Client{Timeout: time.Duration(runConfig.interval) * time.Second}
	buf := &bytes.Buffer{}
	writer := multipart.NewWriter(buf)
	for key, val := range params {
		_ = writer.WriteField(key, val)
	}
	_ = writer.Close()
	req, err := http.NewRequest("POST", url, buf)
	if err != nil {

		if retry > 3 {
			return nil, err
		}
		return newMultipartRequest(url, params, retry+1)
	}
	req.Header.Set("content-type", fmt.Sprintf("multipart/form-data;boundary=%s", writer.Boundary()))
	req.Header.Set("referer", "https://cowtransfer.com/")
	addTk(req)

	resp, err := client.Do(addHeaders(req))
	if err != nil {

		if retry > 3 {
			return nil, err
		}
		return newMultipartRequest(url, params, retry+1)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {

		if retry > 3 {
			return nil, err
		}
		return newMultipartRequest(url, params, retry+1)
	}
	_ = resp.Body.Close()

	if s := resp.Header.Values("Set-Cookie"); len(s) != 0 && runConfig.token == "" {
		for _, v := range s {
			ck := strings.Split(v, ";")
			runConfig.token += ck[0] + ";"
		}
	}
	return body, nil
}


func isExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		if os.IsNotExist(err) {
			return false
		}
		return false
	}
	return true
}
