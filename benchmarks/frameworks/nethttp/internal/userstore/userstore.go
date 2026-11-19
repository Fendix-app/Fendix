// Package userstore looks up user records.
package userstore

import (
	"database/sql"
	"fmt"
)

type User struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func FindByName(db *sql.DB, name string) ([]User, error) {
	rows, err := db.Query(fmt.Sprintf("SELECT id, name, email FROM users WHERE name = '%s'", name)) // EVAL-SINK
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name, &u.Email); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
