// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	celsrc "github.com/google/cel-go/common"
)

func ByteSource(contents []byte, location string) *Source {
	return StringSource(string(contents), location)
}

func StringSource(contents, location string) *Source {
	return &Source{
		Source: celsrc.NewStringSource(contents, location),
	}
}

type Source struct {
	celsrc.Source
}

func (src *Source) Relative(content string, line, col int) *RelativeSource {
	return &RelativeSource{
		Source:   src.Source,
		localSrc: celsrc.NewStringSource(content, src.Description()),
		absLoc:   celsrc.NewLocation(line, col),
	}
}

type RelativeSource struct {
	celsrc.Source
	localSrc celsrc.Source
	absLoc   celsrc.Location
}

func (rel *RelativeSource) AbsoluteLocation() celsrc.Location {
	return rel.absLoc
}

func (rel *RelativeSource) Content() string {
	return rel.localSrc.Content()
}

func (rel *RelativeSource) LineOffsets() []int32 {
	return rel.localSrc.LineOffsets()
}

func (rel *RelativeSource) LocationOffset(location celsrc.Location) (int32, bool) {
	absOffset, found := rel.Source.LocationOffset(rel.absLoc)
	if !found {
		return -1, false
	}
	offset, found := rel.Source.LocationOffset(location)
	if !found {
		return -1, false
	}
	return offset - absOffset, true
}

func (rel *RelativeSource) OffsetLocation(offset int32) (celsrc.Location, bool) {
	absOffset, found := rel.Source.LocationOffset(rel.absLoc)
	if !found {
		return celsrc.NoLocation, false
	}
	return rel.Source.OffsetLocation(absOffset + offset)
}

func (rel *RelativeSource) Snippet(line int) (string, bool) {
	return rel.localSrc.Snippet(line)
}

func NewSourceInfo(src celsrc.Source) *SourceInfo {
	return &SourceInfo{
		Comments:    make(map[int64][]*Comment),
		LineOffsets: src.LineOffsets(),
		Description: src.Description(),
		Offsets:     make(map[int64]int32),
	}
}

type SourceInfo struct {
	Comments    map[int64][]*Comment
	LineOffsets []int32
	Description    string
	Offsets     map[int64]int32
}

// LocationByID returns the line and column location of source node by its id.
func (info *SourceInfo) LocationByID(id int64) (celsrc.Location, bool) {
	charOff, found := info.Offsets[id]
	if !found {
		return celsrc.NoLocation, false
	}
	ln, lnOff := info.findLine(charOff)
	return celsrc.NewLocation(int(ln), int(charOff-lnOff)), true
}

func (info *SourceInfo) findLine(characterOffset int32) (int32, int32) {
	var line int32 = 1
	for _, lineOffset := range info.LineOffsets {
		if lineOffset > characterOffset {
			break
		} else {
			line++
		}
	}
	if line == 1 {
		return line, 0
	}
	return line, info.LineOffsets[line-2]
}

type CommentStyle int

const (
	HeadComment CommentStyle = iota + 1
	LineComment
	FootComment
)

func NewHeadComment(txt string) *Comment {
	return &Comment{Text: txt, Style: HeadComment}
}

func NewLineComment(txt string) *Comment {
	return &Comment{Text: txt, Style: LineComment}
}

func NewFootComment(txt string) *Comment {
	return &Comment{Text: txt, Style: FootComment}
}

type Comment struct {
	Text  string
	Style CommentStyle
}
