// Copyright 2016 The rkt Authors
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

//+build linux

package common

import (
	"fmt"
	"runtime"

	"github.com/appc/spec/schema"
	spec "github.com/opencontainers/runtime-spec/specs-go"
)

// GenerateRuncSpec generates a runc runtime configuration for an application
func GenerateRuncSpec(ra *schema.RuntimeApp, uid, gid int) (*spec.Spec, error) {
	app := ra.App

	// Variables for spec.Process
	additionalGids := make([]uint32, 0, len(app.SupplementaryGIDs))
	for _, g := range app.SupplementaryGIDs {
		additionalGids = append(additionalGids, uint32(g))
	}

	env := make([]string, 0, len(app.Environment))
	for _, envvar := range app.Environment {
		env = append(env, fmt.Sprintf("%s=%s", envvar.Name, envvar.Value))
	}

	capabilities, err := getAppCapabilities(app.Isolators)
	if err != nil {
		return nil, err
	}

	spec := spec.Spec{
		Version: spec.Version,
		Platform: spec.Platform{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Process: spec.Process{
			Terminal: false, //TODO: test with --interactive
			User: spec.User{
				UID:            uint32(uid),
				GID:            uint32(gid),
				AdditionalGids: additionalGids,
			},
			Args:         app.Exec,
			Env:          env,
			Cwd:          app.WorkingDirectory,
			Capabilities: capabilities,
			// RLimits are not supported
			NoNewPrivileges: getAppNoNewPrivileges(app.Isolators),
			// ApparmorProfile is not supported
			SelinuxLabel: getAppSELinuxLabel(app.Isolators),
		},
		Root: spec.Root{
			//TODO: maybe path needed
			Readonly: ra.ReadOnlyRootFS,
		},
		// No hostname - pod level
		// No mounts - pod level
		// TODO(cdc) Hooks
		// No annotations
		// TODO(cdc) Annotations
		Linux: &spec.Linux{
		//TODO(cdc): everything
		},
	}

	return &spec, err
}
