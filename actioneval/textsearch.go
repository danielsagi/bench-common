// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package actioneval

import (
	"bufio"
	"fmt"
	"github.com/aquasecurity/bench-common/common"
	"gopkg.in/yaml.v2"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
)

type TextSearchFilter struct {
	searchLocation string
	filter         string
	filterType     common.YamlEntityValue
}

func NewTextSearchFilter(mapSlice yaml.MapSlice) ISearchFilter {

	filter := new(TextSearchFilter)

	for _, mapItem := range mapSlice {

		key := fmt.Sprintf("%v", mapItem.Key)
		val := fmt.Sprintf("%v", mapItem.Value)

		switch common.YamlEntityName(key) {
		case common.PathEntity:
			filter.searchLocation = val
		case common.FilterEntity:
			filter.filter = val
		case common.FilterTypeEntity:
			filter.filterType = common.YamlEntityValue(val)
		}
	}

	return filter
}

func (ctx *TextSearchFilter) SearchFilterHandler(workspacePath string, count bool) (result SearchFilterResult) {

	rootPath := path.Join(workspacePath, ctx.searchLocation)
	clearRootPath := path.Clean(rootPath)
	// ensure that search location does not escape the workspace
	if !strings.HasPrefix(clearRootPath, workspacePath) {
		result.Errmsgs += common.HandleError(fmt.Errorf("relative path "+rootPath+" are not supported "), reflect.TypeOf(ctx).String())
		result.State = common.FAIL
		return result
	}

	if fileStat, statErr := os.Lstat(clearRootPath); statErr != nil {
		result.Errmsgs += common.HandleError(statErr, reflect.TypeOf(ctx).String())
		result.State = common.FAIL
		return result
	} else {
		if fileStat.Mode()&os.ModeSymlink != 0 { // is link
			// ensure that link does not refer outside of the image path
			var realPath, err = filepath.EvalSymlinks(clearRootPath)
			if err != nil {
				result.Errmsgs += common.HandleError(err, reflect.TypeOf(ctx).String())
				result.State = common.FAIL
				return result
			}

			if !strings.HasPrefix(realPath, workspacePath) {
				result.Errmsgs += common.HandleError(fmt.Errorf("Symbolic link file "+clearRootPath+" refers to "+realPath+" , that is out of image fs scope"), reflect.TypeOf(ctx).String())
				result.State = common.FAIL
				return result
			}
			// ensure this is regular file i.e. not dir or socket file ...
		} else if !fileStat.Mode().IsRegular() {
			result.Errmsgs += common.HandleError(fmt.Errorf("TextSearch accepts only regular files"+fileStat.Name()), reflect.TypeOf(ctx).String())
			result.State = common.FAIL
			return result

		}
	}

	//first step try to open the file
	f, err := os.Open(clearRootPath)
	defer f.Close()

	if err != nil {
		result.Errmsgs += common.HandleError(fmt.Errorf("Unable to open file"+f.Name()), reflect.TypeOf(ctx).String())
		result.State = common.FAIL
		return result
	}

	var match bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		match = false
		for _, word := range strings.Fields(line) {
			if ctx.filterType == common.HasPrefixVal && strings.HasPrefix(word, ctx.filter) ||
				ctx.filterType == common.HasSuffixVal && strings.HasSuffix(word, ctx.filter) ||
				ctx.filterType == common.ContainsVal && strings.Contains(word, ctx.filter) {
				match = true
				break
			}
		}
		if match {
			result.Lines++
			if !count { //append lines when count false , otherwise reserve "out" for counter
				result.Output.WriteString(line + "\n")
			}
		}
	}
	if result.Lines == 0 {
		result.State = common.FAIL
	}
	if count {
		result.Output.WriteString(fmt.Sprintf("%d\n", result.Lines))
	}
	return result
}
