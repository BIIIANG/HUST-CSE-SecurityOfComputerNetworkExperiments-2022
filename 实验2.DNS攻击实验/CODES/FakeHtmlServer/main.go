package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe("172.18.0.1:80", nil))
}

func handler(res http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadFile("/home/seed/Desktop/NetworkSecurity/2022.04.15.DNS/FakeHtmlServer/static/Fake.html")
	if err != nil {
		log.Fatal(err)
	}
	res.Header().Set("Content-Type", "text/html;charset=utf-8")
	_, err = fmt.Fprint(res, string(body))
	if err != nil {
		log.Fatal(err)
	}
}
