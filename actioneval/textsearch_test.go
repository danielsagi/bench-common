package actioneval

import (
	"fmt"
	"github.com/aquasecurity/bench-common/common"
	"github.com/aquasecurity/bench-common/mockdata"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"

	//"os"
	"testing"
)

//create tmp file for that will hold test content
var tmpFile = fmt.Sprintf("%v,%d", "/tmp/test_text_search_content", os.Getpid())

func TestTextSearchFailWrongPath(t *testing.T) {

	var args yaml.MapSlice

	if err := yaml.Unmarshal([]byte(mockdata.TestData1), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v\n", err.Error())
	}
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler("/", false)

	if res.State != common.FAIL {
		t.Errorf("test fail: expected: %v actual: %v\n", common.FAIL, res.State)
	}

}

func TestTextSearchContainsMatch(t *testing.T) {

	var testYaml = fmt.Sprintf(mockdata.TestData2, tmpFile, "able", "contains")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	mockdata.CreateContentFile(tmpFile)
	defer mockdata.DeleteContentFile(tmpFile)
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler("/", false)

	if res.Lines != 3 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", 3, res.Lines, res.Errmsgs)
	}
}

func TestTextSearchHasPrefixMatch(t *testing.T) {

	var testYaml = fmt.Sprintf(mockdata.TestData2, tmpFile, "able", "hasPrefix")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	mockdata.CreateContentFile(tmpFile)
	defer mockdata.DeleteContentFile(tmpFile)
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler("/", false)
	if res.Lines != 2 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", 2, res.Lines, res.Errmsgs)
	}
}

func TestTextSearchHasSuffixMatch(t *testing.T) {

	var testYaml = fmt.Sprintf(mockdata.TestData2, tmpFile, "ing", "hasSuffix")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	mockdata.CreateContentFile(tmpFile)
	defer mockdata.DeleteContentFile(tmpFile)
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler("/", false)
	if res.Lines != 14 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v\n", 15, res.Lines, res.Errmsgs)
	}
}

func TestTextSearchExactContains(t *testing.T) {

	var testYaml = fmt.Sprintf(mockdata.TestData2, tmpFile, "build", "contains")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	mockdata.CreateContentFile(tmpFile)
	defer mockdata.DeleteContentFile(tmpFile)
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler("/", false)
	if res.Lines != 10 {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", 7, res.Lines, res.Errmsgs)
	}
}

func TestTextSearchRelativePathFailure(t *testing.T) {
	var testYaml = fmt.Sprintf(mockdata.TestData2, tmpFile, "build", "exact")
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	mockdata.CreateContentFile(tmpFile)
	defer mockdata.DeleteContentFile(tmpFile)
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler("/root/../../../a.txt", false)
	if res.State != common.FAIL {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", common.FAIL, res.State, res.Errmsgs)
	}
}
func TestTextSearchIntTypes(t *testing.T) {
	var testYaml = fmt.Sprintf(mockdata.TestDataInTypes, tmpFile, 555, 666)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	mockdata.CreateContentFile(tmpFile)
	defer mockdata.DeleteContentFile(tmpFile)
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler("/root/../../../a.txt", false)
	if res.State != common.FAIL {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", common.FAIL, res.State, res.Errmsgs)
	}
}

func TestTextSearchNotRegular(t *testing.T) {
	var testYaml = fmt.Sprintf(mockdata.TestDataInTypes, "/tmp/", 555, 666)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler("/", false)
	if res.State != common.FAIL {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", common.FAIL, res.State, res.Errmsgs)
	}
}

func setupDummyImageFs() (string, error) {

	innerTmpDir, err := ioutil.TempDir("", "myDir")
	if err != nil {
		return "", err
	}

	os.MkdirAll(path.Join(innerTmpDir, "imageroot/etc"), 0777)
	os.MkdirAll(path.Join(innerTmpDir, "outside/etc"), 0777)

	ioutil.WriteFile(path.Join(innerTmpDir, "outside/etc/passwd"), []byte("dfdfd"), 0644)
	os.Symlink(path.Join(innerTmpDir, "outside/etc/passwd"), path.Join(innerTmpDir, "imageroot/etc/passwd.lnk"))

	return innerTmpDir, nil
}

func TestTextSearchLink(t *testing.T) {

	tmpDir, _ := setupDummyImageFs()
	defer os.RemoveAll(tmpDir)

	var testYaml = fmt.Sprintf(mockdata.TestDataInTypes, "/etc/passwd.lnk", 555, 666)
	var args yaml.MapSlice
	if err := yaml.Unmarshal([]byte(testYaml), &args); err != nil {
		t.Errorf("test fail: yaml unmarshal failed %v", err.Error())
	}
	testSearch := NewTextSearchFilter(args)
	var res = testSearch.SearchFilterHandler(path.Join(tmpDir, "/imageroot"), false)
	if res.State != common.FAIL {
		t.Errorf("test fail: expected: %v actual: %v, err: %v", common.FAIL, res.State, res.Errmsgs)
	}
}
