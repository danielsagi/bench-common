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
	"archive/tar"
	"fmt"
	"github.com/aquasecurity/bench-common/common"
	"gopkg.in/yaml.v2"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type tarFileInfo struct {
	tarHeader tar.Header
}

func (ctx *tarFileInfo) Name() string {
	return filepath.Base(ctx.tarHeader.Name)
}

func (ctx *tarFileInfo) Mode() os.FileMode {
	return os.FileMode(convertMode(ctx.tarHeader.Mode))
}

func (ctx *tarFileInfo) Size() int64 {
	return ctx.tarHeader.Size
}

func (ctx *tarFileInfo) ModTime() time.Time {
	return ctx.tarHeader.ModTime
}

func (ctx *tarFileInfo) IsDir() bool {
	// see tar specification for available flags  https://www.freebsd.org/cgi/man.cgi?query=tar&sektion=5&manpath=FreeBSD+8-current
	return ctx.tarHeader.Typeflag&0xD == 0xD
}

func (ctx *tarFileInfo) Sys() interface{} {
	return ctx.tarHeader
}

type FileSearchFilter struct {

	// location where to start the search
	searchLocation string
	// file name filter
	filter string
	// file name filter pattern values contains
	filterType common.TextFilterType

	//file type filter dir or symbolic link
	fileType common.FileFilterType
	// permission 0600,0777,/777 ,-666 etc...
	perm  int64
	smode common.PermissionSearchMode

	tarHeaders []tar.Header

	groupId int64
	userId  int64
}

func (ctx *FileSearchFilter) WithTarHeaders(tarHeaders []tar.Header) *FileSearchFilter {
	ctx.tarHeaders = tarHeaders
	return ctx
}

func NewFileSearchFilter(mapSlice yaml.MapSlice) (filter *FileSearchFilter, err error) {

	filter = new(FileSearchFilter)
	// set default fileTypeFilter
	filter.fileType = common.FileFilterAll
	filter.userId = -1
	filter.groupId = -1
	for _, mapItem := range mapSlice {
		key, val := parseMapKeyValToString(mapItem)

		// parse 'args' section in yaml
		switch common.YamlEntityName(key) {
		case common.PathEntity:
			filter.searchLocation = val
		case common.FilterEntity:
			filter.filter = val
		case common.PermissionEntity:
			if filter.perm, filter.smode, err = parsePermission(val); err != nil {
				return nil, err
			}
		case common.FileTypeEntity:
			filter.fileType = convertFileType(val)
		case common.FilterTypeEntity:
			filter.filterType = convertFilterType(val)
		case common.FilterGroupId:
			if filter.groupId, err = strconv.ParseInt(val, 10, 64); err != nil {
				return nil, err
			}
		case common.FilterUserId:
			if filter.userId, err = strconv.ParseInt(val, 10, 64); err != nil {
				return nil, err
			}
		}
	}
	return filter, nil
}

func parseMapKeyValToString(item yaml.MapItem) (key string, val string) {
	key = fmt.Sprintf("%v", item.Key)
	val = fmt.Sprintf("%v", item.Value)
	return key, val
}

func convertFileType(fileType string) common.FileFilterType {
	switch common.YamlEntityValue(fileType) {
	case common.DirectoryVal:
		return common.FileFilterDirectory
	case common.SymblinkVal:
		return common.FileFilterSymblink
	case common.FileVal:
		return common.FileFilterRegularFile
	default:
		return common.FileFilterAll
	}

}

func convertFilterType(filterType string) common.TextFilterType {
	switch common.YamlEntityValue(filterType) {
	case common.ExactVal:
		return common.TextFilterExact
	case common.HasPrefixVal:
		return common.TextFilterHasPrefix
	case common.HasSuffixVal:
		return common.TextFilterHasSuffix
	case common.ContainsVal:
		fallthrough
	default:
		return common.TextFilterContains
	}
}

func (ctx *FileSearchFilter) SearchFilterHandler(workspacePath string, count bool) (result SearchFilterResult) {

	rootPath := path.Join(workspacePath, ctx.searchLocation)
	clearRootPath := path.Clean(rootPath)

	// ensure that search location does not escape the workspace
	if !strings.HasPrefix(clearRootPath, workspacePath) {
		result.Errmsgs += common.HandleError(fmt.Errorf("relative path "+rootPath+" are not supported "), reflect.TypeOf(ctx).String())
		result.State = common.FAIL
		return result
	}

	walkMethod := func(filePath string, info os.FileInfo, err error) error {

		loc := path.Join("/", filePath)
		if !strings.HasPrefix(loc, path.Clean(ctx.searchLocation)) {
			return nil
		}

		if !ctx.satisfyAllFilters(info) {
			return nil
		}

		result.Lines++
		result.Output.WriteString(loc + "\n")
		return nil
	}

	var walkErr error
	if ctx.tarHeaders == nil {
		walkErr = filepath.Walk(clearRootPath, walkMethod)
	} else {
		for _, header := range ctx.tarHeaders {
			info := &tarFileInfo{tarHeader: header}
			walkMethod(header.Name, info, nil)
		}
	}

	if walkErr != nil {
		result.Errmsgs += common.HandleError(fmt.Errorf(walkErr.Error()), reflect.TypeOf(ctx).String())
		result.State = common.FAIL
		return result
	}
	if count {
		result.Output.Reset()
		result.Output.WriteString(fmt.Sprintf("%d\n", result.Lines))
	}
	return result
}

func (ctx *FileSearchFilter) satisfyGroupIdAnUserIdFilter(info os.FileInfo) bool {

	var uid, gid uint32
	//check groups
	if info.Sys() != nil {
		if ctx.tarHeaders == nil {
			if sys, ok := info.Sys().(*syscall.Stat_t); ok {
				uid = uint32(sys.Uid)
				gid = uint32(sys.Gid)
			}
		} else {
			if sys, ok := info.Sys().(tar.Header); ok {
				uid = uint32(sys.Uid)
				gid = uint32(sys.Gid)
			}
		}
	}

	if ctx.userId != -1 && uint32(ctx.userId) != uid {
		return false
	}

	if ctx.groupId != -1 && uint32(ctx.groupId) != gid {
		return false
	}

	return true
}
func (ctx *FileSearchFilter) satisfyAllFilters(info os.FileInfo) bool {

	if ctx.filter != "" &&
		!ctx.satisfyFilter(info.Name()) {
		return false
	}

	// check if we satisfy the permission filter condition
	if ctx.perm != 0 && ctx.smode != 0 && !ctx.satisfyPermissionFilter(info) {
		return false
	}

	// check if we satisfy the file type filter condition
	if !ctx.satisfyFileType(info) {
		return false
	}

	if !ctx.satisfyGroupIdAnUserIdFilter(info) {
		return false
	}

	return true
}

func (ctx *FileSearchFilter) satisfyPermissionFilter(info os.FileInfo) bool {

	filePerm := int64(info.Mode())
	if (ctx.smode == common.ModeExact && (filePerm&070000777 == ctx.perm)) ||
		(ctx.smode == common.ModeAnyBits && (filePerm&ctx.perm != 0)) ||
		(ctx.smode == common.ModeAllBits && (filePerm&ctx.perm == ctx.perm)) {
		return true
	}
	return false
}

func (ctx *FileSearchFilter) satisfyFilter(filename string) bool {

	if (ctx.filterType == common.TextFilterExact && strings.EqualFold(filename, ctx.filter)) ||
		(ctx.filterType == common.TextFilterHasPrefix && strings.HasPrefix(filename, ctx.filter)) ||
		(ctx.filterType == common.TextFilterHasSuffix && strings.HasSuffix(filename, ctx.filter)) ||
		(ctx.filterType == common.TextFilterContains && strings.Contains(filename, ctx.filter)) {
		return true
	}
	return false
}

//Verify the file type meets the criteria from yaml , i.e dir/symblink oor regular file
func (ctx *FileSearchFilter) satisfyFileType(fileInfo os.FileInfo) bool {

	fileInfo.Mode()
	if (ctx.fileType == common.FileFilterDirectory && fileInfo.IsDir()) ||
		(ctx.fileType == common.FileFilterSymblink && fileInfo.Mode()&os.ModeSymlink != 0) ||
		(ctx.fileType == common.FileFilterRegularFile && fileInfo.Mode().IsRegular()) ||
		(ctx.fileType == common.FileFilterAll) {
		return true
	}
	return false
}

//The permission search mode concept has been taken from unix command "find -perm ",
//which supports 3 modes, recognized by prefix '- or /'
//where '-' prefix means all permission bits are set and  the '/' prefix  means any permissions bits are set.
func parsePermission(perm string) (permInt int64, mode common.PermissionSearchMode, err error) {

	if strings.HasPrefix(perm, "-") { // all permission bits are set for the file
		mode = common.ModeAllBits
	} else if strings.HasPrefix(perm, "/") { // any permissions are set for the file
		mode = common.ModeAnyBits

	} else {
		mode = common.ModeExact
	}
	//strip string form any non numeric chars
	reg, err := regexp.Compile("\\D")
	if err != nil {
		return 0, 0, err
	}

	perm = reg.ReplaceAllString(perm, "")
	if len(perm) == 4 || len(perm) == 3 {
		if permInt, err := strconv.ParseInt(reg.ReplaceAllString(perm, ""), 8, 64); err != nil {
			return 0, 0, err
		} else {
			return int64(convertMode(permInt)), mode, nil
		}
	} else {
		return permInt, mode, fmt.Errorf("invalid permission format %s", perm)
	}
}

// tar mode consist of 12 bits , while os.FileMode consist of 32 bits
// in os.FileMode - first 3 bits represents the setuid/setgid etc.. and last 9 bits represents the mode,
// so the first 3 bits of the tar mode we move to the beginning of 32 bit variable
// and the last 9 bits of the tar mode remains in the same place in new 32 bit variable
func convertMode(mode int64) uint64 {
	return (07000 & uint64(mode) << 12) | uint64(mode)&0777
}
