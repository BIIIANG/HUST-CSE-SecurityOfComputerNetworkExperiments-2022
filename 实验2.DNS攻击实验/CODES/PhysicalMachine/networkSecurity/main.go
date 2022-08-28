package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe("192.168.2.214:80", nil))
}

func handler(res http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadFile("C:\\Users\\86131\\Desktop\\GO\\src\\networkSecurity\\static\\Fake.html")
	if err != nil {
		log.Fatal(err)
	}
	res.Header().Set("Content-Type", "text/html;charset=utf-8")
	_, err = fmt.Fprint(res, string(body))
	if err != nil {
		log.Fatal(err)
	}
}
