package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NHAS/webauthn/protocol"
	"github.com/NHAS/webauthn/webauthn"
)

var (
	web *webauthn.WebAuthn
	err error
)

func main() {
	// Your initialization function
	web, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",                // Display Name for your site
		RPID:          "107.175.28.210",              // Generally the domain name for your site
		RPOrigin:      "https://107.175.28.210:8080", // The origin URL for WebAuthn requests
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	http.HandleFunc("/register/begin/", BeginRegistration)
	http.HandleFunc("/register/finish/", FinishRegistration)

	http.HandleFunc("/login/begin/", BeginLogin)
	http.HandleFunc("/login/finish/", FinishLogin)

	http.Handle("/", http.FileServer(http.Dir("./")))

	serverAddress := ":8080"

	caCert, _ := os.ReadFile("/etc/ssl/cloudflare.crt")

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 加载服务端证书
	srvCert, _ := tls.LoadX509KeyPair("/etc/ssl/bbzbbz.xyz.cert.pem", "/etc/ssl/bbzbbz.xyz.key.pem")

	s := &http.Server{
		Addr:        serverAddress,
		ReadTimeout: 10 * time.Second,
		IdleTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates:       []tls.Certificate{srvCert}, // 服务器证书
			ClientCAs:          caCertPool,                 // 校验客户端的证书 [CA证书]
			ClientAuth:         tls.NoClientCert,           // 校验客户端证书
			InsecureSkipVerify: false,                      // 必须校验 tls

			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		},
	}
	log.Println("starting server at", serverAddress)
	log.Fatal(s.ListenAndServeTLS("", ""))

}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	// get username/friendly name
	username := strings.TrimPrefix(r.URL.Path, "/register/begin/")

	log.Println("beginning registration for: ", username)

	// get user
	user, err := usersDB.GetUser(username)
	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		usersDB.PutUser(user)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := web.BeginRegistration(
		user,
		registerOptions,
	)

	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "registration",
		Value: sessionDb.StartSession(sessionData),
		Path:  "/",
	})

	jsonResponse(w, options, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	// get username/friendly name
	username := strings.TrimPrefix(r.URL.Path, "/register/finish/")

	log.Println("finalising registration for: ", username)

	// get user
	user, err := usersDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("registration")
	if err != nil {
		log.Println("cookie:", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	sessionData, err := sessionDb.GetSession(cookie.Value)
	if err != nil {
		log.Println("cookie:", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := web.FinishRegistration(user, *sessionData, r)
	if err != nil {
		log.Println("finalising: ", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)

	sessionDb.DeleteSession(cookie.Value)

	jsonResponse(w, "Registration Success", http.StatusOK)
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	// get username/friendly name
	username := strings.TrimPrefix(r.URL.Path, "/login/begin/")

	log.Println("user: ", username, "logging in")

	// get user
	user, err := usersDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := web.BeginLogin(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("%+v\n", sessionData)

	http.SetCookie(w, &http.Cookie{
		Name:  "authentication",
		Value: sessionDb.StartSession(sessionData),
		Path:  "/",
	})

	jsonResponse(w, options, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	username := strings.TrimPrefix(r.URL.Path, "/login/finish/")

	log.Println("user: ", username, "finishing logging in")
	// get user
	user, err := usersDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	cookie, err := r.Cookie("authentication")
	if err != nil {
		log.Println("cookie:", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	re, err := json.Marshal(&user)
	if err != nil {
		log.Println("json:", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println(string(re))

	sessionData, err := sessionDb.GetSession(cookie.Value)
	if err != nil {
		log.Println("session:", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	c, err := web.FinishLogin(user, *sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if c.Authenticator.CloneWarning {
		log.Println("cloned key detected")
		jsonResponse(w, "cloned key detected", http.StatusBadRequest)
		return
	}

	sessionDb.DeleteSession(cookie.Value)

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}
