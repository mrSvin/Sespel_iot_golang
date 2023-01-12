package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/auth/signin", Signin)
	http.HandleFunc("/auth/logout", Logout)
	http.HandleFunc("/auth/profile", Profile)

	log.Fatal(http.ListenAndServe(":8000", nil))
}
