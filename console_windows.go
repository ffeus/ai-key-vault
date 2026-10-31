//go:build windows

package main

import "syscall"

// 让 Windows 控制台正确显示中文（切换到 UTF-8 代码页）
func setupConsole() {
	k := syscall.NewLazyDLL("kernel32.dll")
	k.NewProc("SetConsoleOutputCP").Call(65001)
	k.NewProc("SetConsoleCP").Call(65001)
}
