package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
)

type login struct {
	name     string
	password string
	mail     string
	role     string
	photo    []byte
}

func ReadPassword(loginInput string) (string, string, string, string) {
	db := connectToDb()
	defer db.Close()
	return findPassword(db, loginInput)
}

func connectToDb() *sql.DB {
	db, err := sql.Open("mysql", "root:root@tcp(localhost:3306)/stanki_auth")
	if err != nil {
		panic(err)
	}
	return db
}

func findPassword(db *sql.DB, loginInput string) (string, string, string, string) {
	rows, err := db.Query("select username, password, mail, role, photo from users where username=?", loginInput)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	logins := []login{}

	for rows.Next() {
		p := login{}
		err := rows.Scan(&p.name, &p.password, &p.mail, &p.role, &p.photo)
		if err != nil {
			fmt.Println(err)
			continue
		}
		logins = append(logins, p)
	}
	for _, p := range logins {
		return p.password, p.mail, p.role, base64.StdEncoding.EncodeToString(p.photo)
	}
	return "", "", "", ""
}
