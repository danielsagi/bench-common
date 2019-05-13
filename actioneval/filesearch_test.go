package actioneval

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/bench-common/util"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/aquasecurity/bench-common/mockdata"
)

func setUp() (string, error) {

	innerTmpDir, err := ioutil.TempDir("", "myDir")
	if err != nil {
		return "", err
	}

	/// create mock files array

	// go over mock files array and create it on physical device
	for _, item := range mockdata.Mockfiles {
		if item.Ftype == 0 {
			ioutil.WriteFile(path.Join(innerTmpDir, item.File), []byte("test"), item.Perm)
			os.Chmod(path.Join(innerTmpDir, item.File), item.Perm)
		} else if item.Ftype == os.ModeDir {
			os.Mkdir(path.Join(innerTmpDir, item.File), item.Perm)
		} else if item.Ftype == os.ModeSymlink {
			os.Symlink(path.Join(innerTmpDir, "test1"), path.Join(innerTmpDir, item.File))
		}
	}
	return innerTmpDir, nil
}

func TestFileSearchAll(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)
	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchAll, tmpDir)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	var res = fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 24 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 23, res.Lines, res.Errmsgs)
	}
}

func TestFileSearch777(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchPermission, tmpDir, 0777)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 7 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 6, res.Lines, res.Errmsgs)
	}

}

func TestFileSearchFindLinks(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearcByFileType, tmpDir, "symblink")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 6 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 6, res.Lines, res.Errmsgs)
	}

}

func TestFileSearchFindRegular(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearcByFileType, tmpDir, "file")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 11 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 10, res.Lines, res.Errmsgs)
	}

}

func TestFileSearchFindDir(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearcByFileType, tmpDir, "directory")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)

	if res.Lines != 7 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 7, res.Lines, res.Errmsgs)
	}
}

func TestFileSearchFileTypeAndPermission(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchByFileTypeAndPermission, tmpDir, "file", 0700)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 1 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 1, res.Lines, res.Errmsgs)
	}
}

func TestFileSearchDirTypeAndPermission(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchByFileTypeAndPermission, tmpDir, "directory", 0700)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 2 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 2, res.Lines, res.Errmsgs)
	}
}

func TestFileSearchExact(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchByNameFilterAndPerm, tmpDir, "file", 0200, "test6", "exact")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 1 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 1, res.Lines, res.Errmsgs)
	}
}

func TestFileSearchPrefix(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchByNameFilterAndPerm, tmpDir, "file", 0200, "Image", "hasPefix")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 4 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 4, res.Lines, res.Errmsgs)
	}
}

func TestFileSearchSuffix(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchByNameFilterAndPerm, tmpDir, "file", 0200, ".jpg", "hasSuffix")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 4 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 4, res.Lines, res.Errmsgs)
	}
}

func TestFileSearchContains(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchByNameFilter, tmpDir, "/", "test", "contains")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 23 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 22, res.Lines, res.Errmsgs)
	}
}
func TestFileSearchRelativeDir(t *testing.T) {

	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchByNameFilter, tmpDir, "/", "test", "contains")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/root/..//.../aaa", false)
	if res.State != util.FAIL {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", util.FAIL, res.State, res.Errmsgs)
	}
}

func TestFindSetUidFiles(t *testing.T) {
	tmpDir, _ := setUp()
	defer os.RemoveAll(tmpDir)
	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchAllBitsPermission, tmpDir, 04000)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 1 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", 1, res.Lines, res.Errmsgs)
	}
}

func TestWithTarHeaders(t *testing.T) {

	var headers []tar.Header

	if err := json.Unmarshal(mockdata.TarHeadersForTests, &headers); err != nil {
		t.Errorf("test fail: yaml unmarshal tar json %v", err.Error())
		return
	}
	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchPermission, "/etc", 0755)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	fileSearchFilter = fileSearchFilter.WithTarHeaders(headers)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 10 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", 6, res.Lines, res.Errmsgs)
	}
}

func TestWithTarHeadersSetUid(t *testing.T) {

	var headers []tar.Header

	if err := json.Unmarshal(mockdata.TarHeadersForTests, &headers); err != nil {
		t.Errorf("test fail: yaml unmarshal tar json %v", err.Error())
		return
	}
	var testYaml = fmt.Sprintf(mockdata.TestDataFileSearchAllBitsPermission, "/etc", 04000)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	fileSearchFilter, _ := NewFileSearchFilter(args)
	fileSearchFilter = fileSearchFilter.WithTarHeaders(headers)
	res := fileSearchFilter.SearchFilterHandler("/", false)
	if res.Lines != 1 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", 6, res.Lines, res.Errmsgs)
	}
}
