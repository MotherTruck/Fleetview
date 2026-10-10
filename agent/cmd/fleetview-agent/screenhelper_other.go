//go:build !windows && !linux

package main

func runScreenHelperIfRequested() bool { return false }
