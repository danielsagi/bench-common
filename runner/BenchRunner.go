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

package runner

import (
	"archive/tar"
	"errors"
	"fmt"
	"github.com/aquasecurity/bench-common/check"
	"github.com/aquasecurity/bench-common/util"
)

type BenchRunner struct {
	mConfigYaml []byte

	//optional
	mDefinitions []string

	//this file used in FileSearch directive,
	// instead walking thru real FS
	mTarHeaders []tar.Header

	//This directive is used by FileSearch and
	//TextSearch to restrict search folder boundary
	//i.e. only files in this folder are candidates for lookup
	mPathBoundary string

	//This variable used to determine either to run the shell command
	//in yaml 'audit' (i.e. shell cmd)  or 'action' attributes
	mIsActionTest bool

	mControls *check.Controls

	mCheckList string
}

func New(configYaml []byte) (runner *BenchRunner, err error) {

	ctx := new(BenchRunner)
	ctx.mConfigYaml = configYaml
	// validate
	if ctx.mConfigYaml == nil {
		return nil, errors.New("ERROR empty yaml")
	}
	// try to parse the file and get controls
	ctx.mControls, err = ctx.getControls()
	if err != nil {
		return nil, err
	}
	return ctx, nil
}

func (ctx *BenchRunner) WithConstrains(constrains []string) *BenchRunner {
	ctx.mDefinitions = constrains
	return ctx
}

func (ctx *BenchRunner) WithTarHeaders(tarHeaders []tar.Header) *BenchRunner {
	ctx.mTarHeaders = tarHeaders
	return ctx
}

func (ctx *BenchRunner) WithWorkSpace(pathBoundary string) *BenchRunner {
	ctx.mPathBoundary = pathBoundary
	return ctx
}

func (ctx *BenchRunner) WithAction(isAction bool) *BenchRunner {
	ctx.mIsActionTest = isAction
	return ctx
}

func (ctx *BenchRunner) WithCheckList(checkList string) *BenchRunner {
	ctx.mCheckList = checkList
	return ctx
}

func (ctx *BenchRunner) getControls() (*check.Controls, error) {

	controls, err := check.NewControls(ctx.mConfigYaml)
	if err != nil {
		return nil, err
	}
	controls = controls.WithIsAction(ctx.mIsActionTest).
		WithBoundary(ctx.mPathBoundary).
		WithDefinitions(ctx.mDefinitions).
		WithIds(util.CleanIDs(ctx.mCheckList)...).
		WithTarHeaders(ctx.mTarHeaders).
		Build()

	return controls, err
}

func (ctx *BenchRunner) runTests() check.Summary {
	var summary check.Summary
	if ctx.mCheckList != "" {
		summary = ctx.mControls.RunChecks()
	} else {
		summary = ctx.mControls.RunGroup()
	}

	return summary
}

func (ctx *BenchRunner) RunTests() (string, check.Summary, error) {
	summary := ctx.runTests()
	out, err := ctx.mControls.JSON()
	if err != nil {
		return "", summary, err
	}
	return string(out), summary, nil
}

// execute the test and print the result to stdin
func (ctx *BenchRunner) RunTestsWithOutput(jsonFmt bool, noRemediations bool, includeTestOutput bool) error {
	summary := ctx.runTests()
	// if we successfully ran some tests and it's json format, ignore the warnings
	if (summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0) && jsonFmt {
		out, err := ctx.mControls.JSON()
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	} else {
		util.PrettyPrint(ctx.mControls, summary, noRemediations, includeTestOutput)
	}
	return nil
}
