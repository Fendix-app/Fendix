package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

// filesDir is where user-uploaded documents are stored.
const filesDir = "/srv/app/files"

var db *sql.DB

type user struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func scanUsers(rows *sql.Rows) ([]user, error) {
	var users []user
	for rows.Next() {
		var u user
		if err := rows.Scan(&u.ID, &u.Name, &u.Email); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func main() {
	var err error
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /sqli/direct", handleSQLiDirect)
	mux.HandleFunc("GET /sqli/indirect", handleSQLiIndirect)
	mux.HandleFunc("GET /sqli/safe", handleSQLiSafe)
	mux.HandleFunc("GET /sqli/safe-lookalike", handleSQLiSafeLookalike)
	mux.HandleFunc("GET /sqli/cross-file", handleSQLiCrossFile)
	mux.HandleFunc("GET /sqli/alt-api", handleSQLiAltAPI)

	mux.HandleFunc("GET /cmdi/direct", handleCmdiDirect)
	mux.HandleFunc("GET /cmdi/indirect", handleCmdiIndirect)
	mux.HandleFunc("GET /cmdi/safe", handleCmdiSafe)
	mux.HandleFunc("GET /cmdi/safe-lookalike", handleCmdiSafeLookalike)
	mux.HandleFunc("GET /cmdi/cross-file", handleCmdiCrossFile)
	mux.HandleFunc("GET /cmdi/alt-api", handleCmdiAltAPI)

	mux.HandleFunc("GET /xss/direct", handleXSSDirect)
	mux.HandleFunc("GET /xss/indirect", handleXSSIndirect)
	mux.HandleFunc("GET /xss/safe", handleXSSSafe)
	mux.HandleFunc("GET /xss/safe-lookalike", handleXSSSafeLookalike)
	mux.HandleFunc("GET /xss/cross-file", handleXSSCrossFile)
	mux.HandleFunc("GET /xss/alt-api", handleXSSAltAPI)

	mux.HandleFunc("GET /ssrf/direct", handleSSRFDirect)
	mux.HandleFunc("GET /ssrf/indirect", handleSSRFIndirect)
	mux.HandleFunc("GET /ssrf/safe", handleSSRFSafe)
	mux.HandleFunc("GET /ssrf/safe-lookalike", handleSSRFSafeLookalike)
	mux.HandleFunc("GET /ssrf/cross-file", handleSSRFCrossFile)
	mux.HandleFunc("GET /ssrf/alt-api", handleSSRFAltAPI)

	mux.HandleFunc("GET /path-traversal/direct", handlePathTraversalDirect)
	mux.HandleFunc("GET /path-traversal/indirect", handlePathTraversalIndirect)
	mux.HandleFunc("GET /path-traversal/safe", handlePathTraversalSafe)
	mux.HandleFunc("GET /path-traversal/safe-lookalike", handlePathTraversalSafeLookalike)
	mux.HandleFunc("GET /path-traversal/cross-file", handlePathTraversalCrossFile)
	mux.HandleFunc("GET /path-traversal/alt-api", handlePathTraversalAltAPI)

	mux.HandleFunc("GET /open-redirect/direct", handleOpenRedirectDirect)
	mux.HandleFunc("GET /open-redirect/indirect", handleOpenRedirectIndirect)
	mux.HandleFunc("GET /open-redirect/safe", handleOpenRedirectSafe)
	mux.HandleFunc("GET /open-redirect/safe-lookalike", handleOpenRedirectSafeLookalike)
	mux.HandleFunc("GET /open-redirect/cross-file", handleOpenRedirectCrossFile)
	mux.HandleFunc("GET /open-redirect/alt-api", handleOpenRedirectAltAPI)

	mux.HandleFunc("GET /hardcoded-secret/direct", handleHardcodedSecretDirect)
	mux.HandleFunc("GET /hardcoded-secret/indirect", handleHardcodedSecretIndirect)
	mux.HandleFunc("GET /hardcoded-secret/safe", handleHardcodedSecretSafe)
	mux.HandleFunc("GET /hardcoded-secret/safe-lookalike", handleHardcodedSecretSafeLookalike)
	mux.HandleFunc("GET /hardcoded-secret/cross-file", handleHardcodedSecretCrossFile)
	mux.HandleFunc("GET /hardcoded-secret/alt-api", handleHardcodedSecretAltAPI)

	mux.HandleFunc("POST /weak-password-hash/direct", handleWeakPasswordHashDirect)
	mux.HandleFunc("POST /weak-password-hash/indirect", handleWeakPasswordHashIndirect)
	mux.HandleFunc("POST /weak-password-hash/safe", handleWeakPasswordHashSafe)
	mux.HandleFunc("GET /weak-password-hash/safe-lookalike", handleWeakPasswordHashSafeLookalike)

	mux.HandleFunc("GET /jwt-no-verify/direct", handleJWTNoVerifyDirect)
	mux.HandleFunc("GET /jwt-no-verify/indirect", handleJWTNoVerifyIndirect)
	mux.HandleFunc("GET /jwt-no-verify/safe", handleJWTNoVerifySafe)
	mux.HandleFunc("GET /jwt-no-verify/safe-lookalike", handleJWTNoVerifySafeLookalike)

	mux.HandleFunc("POST /weak-random-token/direct", handleWeakRandomTokenDirect)
	mux.HandleFunc("POST /weak-random-token/indirect", handleWeakRandomTokenIndirect)
	mux.HandleFunc("POST /weak-random-token/safe", handleWeakRandomTokenSafe)
	mux.HandleFunc("GET /weak-random-token/safe-lookalike", handleWeakRandomTokenSafeLookalike)

	mux.HandleFunc("GET /ssti/direct", handleSSTIDirect)
	mux.HandleFunc("GET /ssti/indirect", handleSSTIIndirect)
	mux.HandleFunc("GET /ssti/safe", handleSSTISafe)
	mux.HandleFunc("GET /ssti/safe-lookalike", handleSSTISafeLookalike)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
