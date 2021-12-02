package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func CreateZip(Source string,FileName string) bool {
	err := os.RemoveAll(FileName)
	if err != nil {
		return false
	}
	zipfile, _ := os.Create(FileName)
	defer zipfile.Close()
	active := zip.NewWriter(zipfile)
	defer active.Close()
	
	filepath.Walk(Source, func(path string, info fs.FileInfo, err error) error {
		if path == Source {
			return nil
		}
		header,_ := zip.FileInfoHeader(info)
		header.Name = strings.TrimPrefix(path,Source+`\`)
		if info.IsDir() {
			header.Name += `/`
		}else{
			header.Method = zip.Deflate
		}
		writer,_ := active.CreateHeader(header)
		if !info.IsDir(){
			file,_ := os.Open(path)
			defer file.Close()
			_ ,_ = io.Copy(writer,file)
		}
		return nil
	})
	return true
}

var PathName string
var FileName string
func init(){
	flag.StringVar(&PathName,"c","","it will be zip")
	flag.StringVar(&FileName,"o","file.zip","out file name")
	flag.Parse()
}

func main(){
	if PathName != ""{
		if CreateZip(fmt.Sprintf(`%s`,PathName),FileName){
			fmt.Println("zip file success")
		}else{
			fmt.Println("zip file failed")
		}
	}

}

