package main

import (
	"database/sql"
	"log"
	"os"

	"github.com/gin-gonic/gin"
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

func main() {
	var err error
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	r := gin.Default()

	r.GET("/sqli/direct", handleSQLiDirect)
	r.GET("/sqli/indirect", handleSQLiIndirect)
	r.GET("/sqli/safe", handleSQLiSafe)
	r.GET("/sqli/safe-lookalike", handleSQLiSafeLookalike)
	r.GET("/sqli/cross-file", handleSQLiCrossFile)
	r.GET("/sqli/alt-api", handleSQLiAltAPI)

	r.GET("/cmdi/direct", handleCmdiDirect)
	r.GET("/cmdi/indirect", handleCmdiIndirect)
	r.GET("/cmdi/safe", handleCmdiSafe)
	r.GET("/cmdi/safe-lookalike", handleCmdiSafeLookalike)
	r.GET("/cmdi/cross-file", handleCmdiCrossFile)
	r.GET("/cmdi/alt-api", handleCmdiAltAPI)

	r.GET("/xss/direct", handleXSSDirect)
	r.GET("/xss/indirect", handleXSSIndirect)
	r.GET("/xss/safe", handleXSSSafe)
	r.GET("/xss/safe-lookalike", handleXSSSafeLookalike)
	r.GET("/xss/cross-file", handleXSSCrossFile)
	r.GET("/xss/alt-api", handleXSSAltAPI)

	r.GET("/ssrf/direct", handleSSRFDirect)
	r.GET("/ssrf/indirect", handleSSRFIndirect)
	r.GET("/ssrf/safe", handleSSRFSafe)
	r.GET("/ssrf/safe-lookalike", handleSSRFSafeLookalike)
	r.GET("/ssrf/cross-file", handleSSRFCrossFile)
	r.GET("/ssrf/alt-api", handleSSRFAltAPI)

	r.GET("/path-traversal/direct", handlePathTraversalDirect)
	r.GET("/path-traversal/indirect", handlePathTraversalIndirect)
	r.GET("/path-traversal/safe", handlePathTraversalSafe)
	r.GET("/path-traversal/safe-lookalike", handlePathTraversalSafeLookalike)
	r.GET("/path-traversal/cross-file", handlePathTraversalCrossFile)
	r.GET("/path-traversal/alt-api", handlePathTraversalAltAPI)

	r.GET("/open-redirect/direct", handleOpenRedirectDirect)
	r.GET("/open-redirect/indirect", handleOpenRedirectIndirect)
	r.GET("/open-redirect/safe", handleOpenRedirectSafe)
	r.GET("/open-redirect/safe-lookalike", handleOpenRedirectSafeLookalike)
	r.GET("/open-redirect/cross-file", handleOpenRedirectCrossFile)
	r.GET("/open-redirect/alt-api", handleOpenRedirectAltAPI)

	r.GET("/hardcoded-secret/direct", handleHardcodedSecretDirect)
	r.GET("/hardcoded-secret/indirect", handleHardcodedSecretIndirect)
	r.GET("/hardcoded-secret/safe", handleHardcodedSecretSafe)
	r.GET("/hardcoded-secret/safe-lookalike", handleHardcodedSecretSafeLookalike)
	r.GET("/hardcoded-secret/cross-file", handleHardcodedSecretCrossFile)
	r.GET("/hardcoded-secret/alt-api", handleHardcodedSecretAltAPI)

	r.POST("/weak-password-hash/direct", handleWeakPasswordHashDirect)
	r.POST("/weak-password-hash/indirect", handleWeakPasswordHashIndirect)
	r.POST("/weak-password-hash/safe", handleWeakPasswordHashSafe)
	r.GET("/weak-password-hash/safe-lookalike", handleWeakPasswordHashSafeLookalike)

	r.GET("/jwt-no-verify/direct", handleJWTNoVerifyDirect)
	r.GET("/jwt-no-verify/indirect", handleJWTNoVerifyIndirect)
	r.GET("/jwt-no-verify/safe", handleJWTNoVerifySafe)
	r.GET("/jwt-no-verify/safe-lookalike", handleJWTNoVerifySafeLookalike)

	r.POST("/weak-random-token/direct", handleWeakRandomTokenDirect)
	r.POST("/weak-random-token/indirect", handleWeakRandomTokenIndirect)
	r.POST("/weak-random-token/safe", handleWeakRandomTokenSafe)
	r.GET("/weak-random-token/safe-lookalike", handleWeakRandomTokenSafeLookalike)

	r.GET("/ssti/direct", handleSSTIDirect)
	r.GET("/ssti/indirect", handleSSTIIndirect)
	r.GET("/ssti/safe", handleSSTISafe)
	r.GET("/ssti/safe-lookalike", handleSSTISafeLookalike)

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
