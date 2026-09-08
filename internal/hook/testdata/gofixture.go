package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("pid=%d ppid=%d\n", os.Getpid(), os.Getppid())
	if err := os.WriteFile("go-fixture.txt", []byte("Go library calls\n"), 0600); err != nil {
		panic(err)
	}
	data, err := os.ReadFile("go-fixture.txt")
	if err != nil {
		panic(err)
	}
	if err := os.Remove("go-fixture.txt"); err != nil {
		panic(err)
	}
	os.Stdout.Write(data)
}
