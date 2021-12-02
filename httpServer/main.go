package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"strings"
)

var address string
var dir string
var Username string
var Password string

func httpServer(Username,Password string)  {
	if Username == "" && Password == "" {
		_ = http.ListenAndServe(address, http.FileServer(http.Dir(dir)))
	}
	_ = http.ListenAndServe(address, SimpleBasicAuth(Username, Password)(http.FileServer(http.Dir(dir))))
}
//身份认证

type basicAuth struct {
	h    http.Handler
	opts AuthOptions
}
//身份认证

type AuthOptions struct {
	Realm               string
	User                string
	Password            string
	AuthFunc            func(string, string, *http.Request) bool
	UnauthorizedHandler http.Handler
}


func (b basicAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.opts.UnauthorizedHandler == nil {
		b.opts.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}
	if b.authenticate(r) == false {
		b.requestAuth(w, r)
		return
	}
	b.h.ServeHTTP(w, r)
}

func (b *basicAuth) authenticate(r *http.Request) bool {
	const basicScheme string = "Basic "

	if r == nil {
		return false
	}
	if b.opts.AuthFunc == nil && b.opts.User == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, basicScheme) {
		return false
	}
	str, err := base64.StdEncoding.DecodeString(auth[len(basicScheme):])
	if err != nil {
		return false
	}
	cred := bytes.SplitN(str, []byte(":"), 2)
	if len(cred) != 2 {
		return false
	}
	givenUser := string(cred[0])
	givenPass := string(cred[1])
	if b.opts.AuthFunc == nil {
		b.opts.AuthFunc = b.simpleBasicAuthFunc
	}

	return b.opts.AuthFunc(givenUser, givenPass, r)
}


func (b *basicAuth) simpleBasicAuthFunc(user, pass string, r *http.Request) bool {
	givenUser := sha256.Sum256([]byte(user))
	givenPass := sha256.Sum256([]byte(pass))
	requiredUser := sha256.Sum256([]byte(b.opts.User))
	requiredPass := sha256.Sum256([]byte(b.opts.Password))
	if subtle.ConstantTimeCompare(givenUser[:], requiredUser[:]) == 1 &&
		subtle.ConstantTimeCompare(givenPass[:], requiredPass[:]) == 1 {
		return true
	}

	return false
}

func (b *basicAuth) requestAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, b.opts.Realm))
	b.opts.UnauthorizedHandler.ServeHTTP(w, r)
}

func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func BasicAuth(o AuthOptions) func(http.Handler) http.Handler {
	fn := func(h http.Handler) http.Handler {
		return basicAuth{h, o}
	}
	return fn
}

func SimpleBasicAuth(user, password string) func(http.Handler) http.Handler {
	opts := AuthOptions{
		Realm:    "Restricted",
		User:     user,
		Password: password,
	}
	return BasicAuth(opts)
}

func init(){
	flag.StringVar(&address,"m","127.0.0.1:8889","http server address")
	flag.StringVar(&dir,"d","./","http server will use dir")
	flag.StringVar(&Username,"u","","Auth Username")
	flag.StringVar(&Password,"p","","Auth Password")
	flag.Parse()
}

func main(){
	//address = "127.0.0.1:8889"
	httpServer(Username,Password)
}