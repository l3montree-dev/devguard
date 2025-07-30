package main

import (
	"fmt"
	"net/url"
)

func main() {
	fmt.Println("Testing url.PathEscape:")
	fmt.Printf("react/dom -> %s\n", url.PathEscape("react/dom"))
	fmt.Printf("github.com/test/pkg -> %s\n", url.PathEscape("github.com/test/pkg"))
	fmt.Printf("django/contrib -> %s\n", url.PathEscape("django/contrib"))
}
