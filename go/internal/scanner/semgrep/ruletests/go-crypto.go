//go:build ignore

// Rule tests for rules/go-crypto.yaml: weak password hashing, JWTs trusted
// without signature verification and math/rand tokens in net/http and Gin
// handlers. go-crypto.cryptorand.go holds the crypto/rand cases: one file
// cannot import both packages as rand. See README.md.
package ruletests

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// --- Weak password hashing --------------------------------------------------------

func registerNetHTTP(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	// ruleid: go-weak-password-hash-taint
	sum := md5.Sum([]byte(password))
	storeUser(r.FormValue("username"), hex.EncodeToString(sum[:]))
	// ok: go-weak-password-hash-taint
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	storeUser(r.FormValue("username"), string(hash))
	// ok: go-weak-password-hash-taint
	avatar := md5.Sum([]byte(strings.ToLower(r.FormValue("email"))))
	_ = avatar
}

func registerIndirect(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	// ruleid: go-weak-password-hash-taint
	storeUser(r.FormValue("username"), HashPassword(password))
}

func registerGin(c *gin.Context) {
	h := sha1.New()
	// ruleid: go-weak-password-hash-taint
	h.Write([]byte(c.PostForm("password")))
	// ruleid: go-weak-password-hash-taint
	storeUser(c.PostForm("username"), HashPassword(c.PostForm("password")))
}

// A generic MD5 helper: the password is named at the call.
func login(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-weak-password-hash-taint
	digest := md5Hex(r.FormValue("password"))
	// ok: go-weak-password-hash-taint
	etag := md5Hex(r.FormValue("document"))
	storeUser(digest, etag)
}

func md5Hex(text string) string {
	hasher := md5.New()
	// ok: go-weak-password-hash-sink
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func HashPassword(password string) string {
	// ruleid: go-weak-password-hash-sink
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:])
}

func catalogETag(data []byte) string {
	// ok: go-weak-password-hash-sink
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

func storeUser(name, hash string) {}

// --- JWT trusted without verifying its signature -----------------------------------

func jwtNetHTTP(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// ruleid: go-jwt-no-verify-taint
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["role"] != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

var jwtKeysByID = map[string][]byte{"primary": []byte(os.Getenv("JWT_PRIMARY_KEY"))}

// Reading only the unverified header to choose a key, then verifying.
func jwtKeyID(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// ok: go-jwt-no-verify-taint
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return
	}
	kid, _ := unverified.Header["kid"].(string)
	key := jwtKeysByID[kid]
	// ok: go-jwt-no-verify-taint
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		return
	}
	_ = token.Claims
}

func jwtIndirect(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// ruleid: go-jwt-no-verify-taint
	ClaimsFromToken(tokenString)
}

func jwtGin(c *gin.Context) {
	// ruleid: go-jwt-no-verify-taint
	claims, err := ClaimsFromToken(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": claims["sub"]})
}

func ClaimsFromToken(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	// ruleid: go-jwt-no-verify-sink
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// jwt.Parse with a key function verifies the signature.
func jwtVerified(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// ok: go-jwt-no-verify-taint
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) { return jwtKeysByID["primary"], nil })
	if err != nil || !token.Valid {
		return
	}
	_ = token.Claims
	parser := jwt.NewParser()
	// ruleid: go-jwt-no-verify-taint
	unverified, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return
	}
	_ = unverified.Claims
}

func keyIDFromToken(tokenString string) string {
	// ok: go-jwt-no-verify-sink
	t, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return ""
	}
	kid, _ := t.Header["kid"].(string)
	return kid
}

// --- Tokens from math/rand ----------------------------------------------------------

const letters = "abcdefghijklmnopqrstuvwxyz0123456789"

func passwordReset(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-weak-random-token
	token := fmt.Sprintf("%016x%016x", rand.Uint64(), rand.Uint64())
	storeUser(r.FormValue("email"), token)
	// ok: go-weak-random-token
	delay := time.Duration(rand.Intn(250)) * time.Millisecond
	time.Sleep(delay)
}

func newSessionID() string {
	b := make([]byte, 24)
	for i := range b {
		// ruleid: go-weak-random-token
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func generateAPIKey() string {
	b := make([]byte, 32)
	// ruleid: go-weak-random-token
	rand.Read(b)
	return hex.EncodeToString(b)
}

// The secret word must be the name's last segment: a delay or a timeout for a
// reset or a session is not a secret.
func randomNames(w http.ResponseWriter, r *http.Request) {
	// ok: go-weak-random-token
	resetDelayMs := rand.Intn(500)
	// ok: go-weak-random-token
	sessionTimeout := time.Duration(rand.Intn(30)) * time.Minute
	// ok: go-weak-random-token
	tokenRefreshJitter := rand.Int63n(1000)
	// ok: go-weak-random-token
	spotPrice := rand.Float64() * 100
	// ruleid: go-weak-random-token
	resetToken := fmt.Sprintf("%x", rand.Uint64())
	// ruleid: go-weak-random-token
	sessionID := rand.Int63()
	// ruleid: go-weak-random-token
	apiKey := fmt.Sprintf("%016x", rand.Uint64())
	// ruleid: go-weak-random-token
	otp := rand.Intn(1000000)
	fmt.Fprintln(w, resetDelayMs, sessionTimeout, tokenRefreshJitter, spotPrice, resetToken, sessionID, apiKey, otp)
}

type loginSession struct {
	Token   string
	Timeout int
}

func refreshSession(s *loginSession) {
	// ruleid: go-weak-random-token
	s.Token = fmt.Sprintf("%x", rand.Uint64())
	// ok: go-weak-random-token
	s.Timeout = rand.Intn(60)
}

func newOTP() int {
	// ruleid: go-weak-random-token
	return rand.Intn(1000000)
}

// An acronym before the secret word.
func GenerateCSRFToken() int {
	// ruleid: go-weak-random-token
	return rand.Intn(1000000)
}

func newAPIToken() string {
	// ruleid: go-weak-random-token
	return fmt.Sprintf("%x", rand.Uint64())
}

func GenerateSessionTimeout() int {
	// ok: go-weak-random-token
	return rand.Intn(100)
}

func sessionTimeoutJitter() int {
	// ok: go-weak-random-token
	return rand.Intn(1000)
}

// A handler whose name mentions tokens, using math/rand for something else.
func handleTokenPageFeatured(w http.ResponseWriter, r *http.Request) {
	items := []string{"a", "b", "c"}
	// ok: go-weak-random-token
	rand.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
}

// --- Weak password hashing: unknown calls keep the input's taint -------------------------

func paddedPassword(p string) string {
	out := p + "-pad"
	return out
}

func hashUnknownCalls(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	// ruleid: go-weak-password-hash-taint
	md5.Sum([]byte(otherFilePassword(password)))
	// ruleid: go-weak-password-hash-taint
	md5.Sum([]byte(paddedPassword(password)))
}
