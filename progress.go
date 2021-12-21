package main

import "glint/plugin"

//进度条模块

type Progress struct {
	TaskId   int
	Progress uint32
	Plugin   []*plugin.Plugin
}
