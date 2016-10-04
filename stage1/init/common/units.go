// Copyright 2014 The rkt Authors
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
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/appc/spec/schema"
	"github.com/appc/spec/schema/types"
	"github.com/coreos/rkt/common/cgroup"
	"github.com/coreos/rkt/pkg/user"
	stage1commontypes "github.com/coreos/rkt/stage1/common/types"

	"github.com/coreos/go-systemd/unit"
	"github.com/coreos/rkt/common"
	"github.com/hashicorp/errwrap"
)

func MutableEnv(p *stage1commontypes.Pod) error {
	w := NewUnitWriter(p)

	w.WriteUnit(
		TargetUnitPath(p.Root, "default"),
		"failed to write default.target",
		unit.NewUnitOption("Unit", "Description", "rkt apps target"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "Requires", "systemd-journald.service"),
		unit.NewUnitOption("Unit", "After", "systemd-journald.service"),
		unit.NewUnitOption("Unit", "Before", "halt.target"),
		unit.NewUnitOption("Unit", "Conflicts", "halt.target"),
	)

	w.WriteUnit(
		ServiceUnitPath(p.Root, "prepare-app@"),
		"failed to write prepare-app service template",
		unit.NewUnitOption("Unit", "Description", "Prepare minimum environment for chrooted applications"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "OnFailureJobMode", "fail"),
		unit.NewUnitOption("Service", "Type", "oneshot"),
		unit.NewUnitOption("Service", "Restart", "no"),
		unit.NewUnitOption("Service", "ExecStart", "/prepare-app %I"),
		unit.NewUnitOption("Service", "User", "0"),
		unit.NewUnitOption("Service", "Group", "0"),
		unit.NewUnitOption("Service", "CapabilityBoundingSet", "CAP_SYS_ADMIN CAP_DAC_OVERRIDE"),
	)

	w.WriteUnit(
		TargetUnitPath(p.Root, "halt"),
		"failed to write halt target",
		unit.NewUnitOption("Unit", "Description", "Halt"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "AllowIsolate", "true"),
		unit.NewUnitOption("Unit", "Requires", "shutdown.service"),
		unit.NewUnitOption("Unit", "After", "shutdown.service"),
	)

	w.writeShutdownService(
		"ExecStart",
		unit.NewUnitOption("Unit", "Description", "Pod shutdown"),
		unit.NewUnitOption("Unit", "AllowIsolate", "true"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Service", "RemainAfterExit", "yes"),
	)

	return w.Error()
}

func ImmutableEnv(p *stage1commontypes.Pod, interactive bool, privateUsers string, insecureOptions Stage1InsecureOptions) error {
	w := NewUnitWriter(p)

	opts := []*unit.UnitOption{
		unit.NewUnitOption("Unit", "Description", "rkt apps target"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
	}

	for i := range p.Manifest.Apps {
		ra := &p.Manifest.Apps[i]
		serviceName := ServiceUnitName(ra.Name)
		opts = append(opts, unit.NewUnitOption("Unit", "After", serviceName))
		opts = append(opts, unit.NewUnitOption("Unit", "Wants", serviceName))
	}

	w.WriteUnit(
		TargetUnitPath(p.Root, "default"),
		"failed to write default.target",
		opts...,
	)

	w.WriteUnit(
		ServiceUnitPath(p.Root, "prepare-app@"),
		"failed to write prepare-app service template",
		unit.NewUnitOption("Unit", "Description", "Prepare minimum environment for chrooted applications"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "OnFailureJobMode", "fail"),
		unit.NewUnitOption("Unit", "Requires", "systemd-journald.service"),
		unit.NewUnitOption("Unit", "After", "systemd-journald.service"),
		unit.NewUnitOption("Service", "Type", "oneshot"),
		unit.NewUnitOption("Service", "Restart", "no"),
		unit.NewUnitOption("Service", "ExecStart", "/prepare-app %I"),
		unit.NewUnitOption("Service", "User", "0"),
		unit.NewUnitOption("Service", "Group", "0"),
		unit.NewUnitOption("Service", "CapabilityBoundingSet", "CAP_SYS_ADMIN CAP_DAC_OVERRIDE"),
	)

	w.WriteUnit(
		TargetUnitPath(p.Root, "halt"),
		"failed to write halt target",
		unit.NewUnitOption("Unit", "Description", "Halt"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "AllowIsolate", "true"),
	)

	w.writeShutdownService(
		"ExecStop",
		unit.NewUnitOption("Unit", "Description", "Pod shutdown"),
		unit.NewUnitOption("Unit", "AllowIsolate", "true"),
		unit.NewUnitOption("Unit", "StopWhenUnneeded", "yes"),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Service", "RemainAfterExit", "yes"),
	)

	if err := w.Error(); err != nil {
		return err
	}

	for i := range p.Manifest.Apps {
		ra := &p.Manifest.Apps[i]

		if ra.App.WorkingDirectory == "" {
			ra.App.WorkingDirectory = "/"
		}

		binPath, err := FindBinPath(p, ra)
		if err != nil {
			return err
		}

		var opts []*unit.UnitOption
		if interactive {
			opts = append(opts, unit.NewUnitOption("Service", "StandardInput", "tty"))
			opts = append(opts, unit.NewUnitOption("Service", "StandardOutput", "tty"))
			opts = append(opts, unit.NewUnitOption("Service", "StandardError", "tty"))
		} else {
			opts = append(opts, unit.NewUnitOption("Service", "StandardOutput", "journal+console"))
			opts = append(opts, unit.NewUnitOption("Service", "StandardError", "journal+console"))
		}
		w.AppUnit(ra, binPath, privateUsers, insecureOptions, opts...)

		w.AppReaperUnit(ra.Name, binPath,
			unit.NewUnitOption("Unit", "Wants", "shutdown.service"),
			unit.NewUnitOption("Unit", "After", "shutdown.service"),
		)
	}

	return w.Error()
}

// UnitWriter is the type that writes systemd units preserving the first previously occured error.
// Any method of this type can be invoked multiple times without error checking.
// If a previous invocation generated an error, any invoked method will be skipped.
// If an error occured during method invocations, it can be retrieved using Error().
type UnitWriter struct {
	err error
	p   *stage1commontypes.Pod
}

// NewUnitWriter returns a new UnitWriter for the given pod.
func NewUnitWriter(p *stage1commontypes.Pod) *UnitWriter {
	return &UnitWriter{p: p}
}

// WriteUnit writes a systemd unit in the given path with the given unit options
// if no previous error occured.
func (uw *UnitWriter) WriteUnit(path string, errmsg string, opts ...*unit.UnitOption) {
	if uw.err != nil {
		return
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		uw.err = errwrap.Wrap(errors.New(errmsg), err)
		return
	}
	defer file.Close()

	if _, err = io.Copy(file, unit.Serialize(opts)); err != nil {
		uw.err = errwrap.Wrap(errors.New(errmsg), err)
	}
}

// writeShutdownService writes a shutdown.service unit with the given unit options
// if no previous error occured.
// exec specifies how systemctl should be invoked, i.e. ExecStart, or ExecStop.
func (uw *UnitWriter) writeShutdownService(exec string, opts ...*unit.UnitOption) {
	if uw.err != nil {
		return
	}

	flavor, systemdVersion, err := GetFlavor(uw.p)
	if err != nil {
		uw.err = errwrap.Wrap(errors.New("failed to create shutdown service"), err)
		return
	}

	opts = append(opts, []*unit.UnitOption{
		// The default stdout is /dev/console (the tty created by nspawn).
		// But the tty might be destroyed if rkt is executed via ssh and
		// the user terminates the ssh session. We still want
		// shutdown.service to succeed in that case, so don't use
		// /dev/console.
		unit.NewUnitOption("Service", "StandardInput", "null"),
		unit.NewUnitOption("Service", "StandardOutput", "null"),
		unit.NewUnitOption("Service", "StandardError", "null"),
	}...)

	shutdownVerb := "exit"
	// systemd <v227 doesn't allow the "exit" verb when running as PID 1, so
	// use "halt".
	// If systemdVersion is 0 it means it couldn't be guessed, assume it's new
	// enough for "systemctl exit".
	// This can happen, for example, when building rkt with:
	//
	// ./configure --with-stage1-flavors=src --with-stage1-systemd-version=master
	//
	// The patches for the "exit" verb are backported to the "coreos" flavor, so
	// don't rely on the systemd version on the "coreos" flavor.
	if flavor != "coreos" && systemdVersion != 0 && systemdVersion < 227 {
		shutdownVerb = "halt"
	}

	opts = append(
		opts,
		unit.NewUnitOption("Service", exec, fmt.Sprintf("/usr/bin/systemctl --force %s", shutdownVerb)),
	)

	uw.WriteUnit(
		ServiceUnitPath(uw.p.Root, "shutdown"),
		"failed to create shutdown service",
		opts...,
	)
}

// Activate actives the given unit in the given wantPath.
func (uw *UnitWriter) Activate(unit, wantPath string) {
	if uw.err != nil {
		return
	}

	if err := os.Symlink(path.Join("..", unit), wantPath); err != nil && !os.IsExist(err) {
		uw.err = errwrap.Wrap(errors.New("failed to link service want"), err)
	}
}

// error returns the first error that occured during write* invocations.
func (uw *UnitWriter) Error() error {
	return uw.err
}

func (uw *UnitWriter) AppUnit(
	ra *schema.RuntimeApp, binPath, privateUsers string, insecureOptions Stage1InsecureOptions,
	opts ...*unit.UnitOption,
) {
	if uw.err != nil {
		return
	}

	flavor, _, err := GetFlavor(uw.p)
	if err != nil {
		uw.err = errwrap.Wrap(errors.New("failed to create shutdown service"), err)
		return
	}

	app := ra.App
	appName := ra.Name
	imgName := uw.p.AppNameToImageName(appName)

	if len(app.Exec) == 0 {
		uw.err = fmt.Errorf(`image %q has an empty "exec" (try --exec=BINARY)`, imgName)
		return
	}

	env := app.Environment

	env.Set("AC_APP_NAME", appName.String())
	if uw.p.MetadataServiceURL != "" {
		env.Set("AC_METADATA_URL", uw.p.MetadataServiceURL)
	}

	envFilePath := EnvFilePath(uw.p.Root, appName)

	uidRange := user.NewBlankUidRange()
	if err := uidRange.Deserialize([]byte(privateUsers)); err != nil {
		uw.err = err
		return
	}

	if err := common.WriteEnvFile(env, uidRange, envFilePath); err != nil {
		uw.err = errwrap.Wrap(errors.New("unable to write environment file for systemd"), err)
		return
	}

	u, g, err := parseUserGroup(uw.p, ra, uidRange)
	if err != nil {
		uw.err = err
		return
	}

	if err := generateSysusers(uw.p, ra, u, g, uidRange); err != nil {
		uw.err = errwrap.Wrap(errors.New("unable to generate sysusers"), err)
		return
	}

	var supplementaryGroups []string
	for _, g := range app.SupplementaryGIDs {
		supplementaryGroups = append(supplementaryGroups, strconv.Itoa(g))
	}

	capabilitiesStr, err := getAppCapabilities(app.Isolators)
	if err != nil {
		uw.err = err
		return
	}

	execStart := append([]string{binPath}, app.Exec[1:]...)
	execStartString := quoteExec(execStart)
	opts = append(opts, []*unit.UnitOption{
		unit.NewUnitOption("Unit", "Description", fmt.Sprintf("Application=%v Image=%v", appName, imgName)),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "Wants", fmt.Sprintf("reaper-%s.service", appName)),
		unit.NewUnitOption("Service", "Restart", "no"),
		unit.NewUnitOption("Service", "ExecStart", execStartString),
		unit.NewUnitOption("Service", "RootDirectory", common.RelAppRootfsPath(appName)),
		// MountFlags=shared creates a new mount namespace and (as unintuitive
		// as it might seem) makes sure the mount is slave+shared.
		unit.NewUnitOption("Service", "MountFlags", "shared"),
		unit.NewUnitOption("Service", "WorkingDirectory", app.WorkingDirectory),
		unit.NewUnitOption("Service", "EnvironmentFile", RelEnvFilePath(appName)),
		unit.NewUnitOption("Service", "User", strconv.Itoa(u)),
		unit.NewUnitOption("Service", "Group", strconv.Itoa(g)),
		unit.NewUnitOption("Service", "SupplementaryGroups", strings.Join(supplementaryGroups, " ")),

		// This helps working around a race
		// (https://github.com/systemd/systemd/issues/2913) that causes the
		// systemd unit name not getting written to the journal if the unit is
		// short-lived and runs as non-root.
		unit.NewUnitOption("Service", "SyslogIdentifier", appName.String()),
	}...)

	if supportsNotify(uw.p, appName.String()) {
		opts = append(opts, unit.NewUnitOption("Service", "Type", "notify"))
	}

	if !insecureOptions.DisableCapabilities {
		opts = append(opts, unit.NewUnitOption("Service", "CapabilityBoundingSet", strings.Join(capabilitiesStr, " ")))
	}

	noNewPrivileges := getAppNoNewPrivileges(app.Isolators)

	// Apply seccomp isolator, if any and not opt-ing out;
	// see https://www.freedesktop.org/software/systemd/man/systemd.exec.html#SystemCallFilter=
	if !insecureOptions.DisableSeccomp {
		var forceNoNewPrivileges bool

		unprivileged := (u != 0)
		opts, forceNoNewPrivileges, err = getSeccompFilter(opts, uw.p, unprivileged, app.Isolators)
		if err != nil {
			uw.err = err
			return
		}

		// Seccomp filters require NoNewPrivileges for unprivileged apps, that may override
		// manifest annotation.
		if forceNoNewPrivileges {
			noNewPrivileges = true
		}
	}

	opts = append(opts, unit.NewUnitOption("Service", "NoNewPrivileges", strconv.FormatBool(noNewPrivileges)))

	if ra.ReadOnlyRootFS {
		opts = append(opts, unit.NewUnitOption("Service", "ReadOnlyDirectories", common.RelAppRootfsPath(appName)))
	}

	// TODO(tmrts): Extract this logic into a utility function.
	vols := make(map[types.ACName]types.Volume)
	for _, v := range uw.p.Manifest.Volumes {
		vols[v.Name] = v
	}

	absRoot, err := filepath.Abs(uw.p.Root) // Absolute path to the pod's rootfs.
	if err != nil {
		uw.err = err
		return
	}
	appRootfs := common.AppRootfsPath(absRoot, appName)

	rwDirs := []string{}
	imageManifest := uw.p.Images[appName.String()]
	mounts := GenerateMounts(ra, vols, imageManifest)
	for _, m := range mounts {
		mntPath, err := EvaluateSymlinksInsideApp(appRootfs, m.Path)
		if err != nil {
			uw.err = err
			return
		}

		if !IsMountReadOnly(vols[m.Volume], app.MountPoints) {
			rwDirs = append(rwDirs, filepath.Join(common.RelAppRootfsPath(appName), mntPath))
		}
	}

	// Restrict access to sensitive paths (eg. procfs) and devices. For kvm flavor,
	// these paths are stored inside the vm, without influence to the host.
	if !insecureOptions.DisablePaths && flavor != "kvm" {
		opts = protectSystemFiles(opts, appName)
		opts = append(opts, unit.NewUnitOption("Service", "DevicePolicy", "closed"))
		deviceAllows, err := generateDeviceAllows(common.Stage1RootfsPath(absRoot), appName, app.MountPoints, mounts, vols, uidRange)
		if err != nil {
			uw.err = err
			return
		}
		for _, dev := range deviceAllows {
			opts = append(opts, unit.NewUnitOption("Service", "DeviceAllow", dev))
		}
	}

	opts = append(opts, unit.NewUnitOption("Service", "ReadWriteDirectories", strings.Join(rwDirs, " ")))
	// When an app fails, we shut down the pod
	opts = append(opts, unit.NewUnitOption("Unit", "OnFailure", "halt.target"))

	for _, eh := range app.EventHandlers {
		var typ string
		switch eh.Name {
		case "pre-start":
			typ = "ExecStartPre"
		case "post-stop":
			typ = "ExecStopPost"
		default:
			uw.err = fmt.Errorf("unrecognized eventHandler: %v", eh.Name)
			return
		}
		exec := quoteExec(eh.Exec)
		opts = append(opts, unit.NewUnitOption("Service", typ, exec))
	}

	// Some pre-start jobs take a long time, set the timeout to 0
	opts = append(opts, unit.NewUnitOption("Service", "TimeoutStartSec", "0"))

	var saPorts []types.Port
	for _, p := range app.Ports {
		if p.SocketActivated {
			saPorts = append(saPorts, p)
		}
	}

	for _, i := range app.Isolators {
		switch v := i.Value().(type) {
		case *types.ResourceMemory:
			opts, err = cgroup.MaybeAddIsolator(opts, "memory", v.Limit())
			if err != nil {
				uw.err = err
				return
			}
		case *types.ResourceCPU:
			opts, err = cgroup.MaybeAddIsolator(opts, "cpu", v.Limit())
			if err != nil {
				uw.err = err
				return
			}
		case *types.LinuxOOMScoreAdj:
			opts = append(opts, unit.NewUnitOption("Service", "OOMScoreAdjust", strconv.Itoa(int(*v))))
		}
	}

	if len(saPorts) > 0 {
		sockopts := []*unit.UnitOption{
			unit.NewUnitOption("Unit", "Description", fmt.Sprintf("Application=%v Image=%v %s", appName, imgName, "socket-activated ports")),
			unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
			unit.NewUnitOption("Socket", "BindIPv6Only", "both"),
			unit.NewUnitOption("Socket", "Service", ServiceUnitName(appName)),
		}

		for _, sap := range saPorts {
			var proto string
			switch sap.Protocol {
			case "tcp":
				proto = "ListenStream"
			case "udp":
				proto = "ListenDatagram"
			default:
				uw.err = fmt.Errorf("unrecognized protocol: %v", sap.Protocol)
				return
			}
			// We find the host port for the pod's port and use that in the
			// socket unit file.
			// This is so because systemd inside the pod will match based on
			// the socket port number, and since the socket was created on the
			// host, it will have the host port number.
			port := findHostPort(*uw.p.Manifest, sap.Name)
			if port == 0 {
				log.Printf("warning: no --port option for socket-activated port %q, assuming port %d as specified in the manifest", sap.Name, sap.Port)
				port = sap.Port
			}
			sockopts = append(sockopts, unit.NewUnitOption("Socket", proto, fmt.Sprintf("%v", port)))
		}

		file, err := os.OpenFile(SocketUnitPath(uw.p.Root, appName), os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			uw.err = errwrap.Wrap(errors.New("failed to create socket file"), err)
			return
		}
		defer file.Close()

		if _, err = io.Copy(file, unit.Serialize(sockopts)); err != nil {
			uw.err = errwrap.Wrap(errors.New("failed to write socket unit file"), err)
			return
		}

		if err = os.Symlink(path.Join("..", SocketUnitName(appName)), SocketWantPath(uw.p.Root, appName)); err != nil {
			uw.err = errwrap.Wrap(errors.New("failed to link socket want"), err)
			return
		}

		opts = append(opts, unit.NewUnitOption("Unit", "Requires", SocketUnitName(appName)))
	}

	opts = append(opts, unit.NewUnitOption("Unit", "Requires", InstantiatedPrepareAppUnitName(appName)))
	opts = append(opts, unit.NewUnitOption("Unit", "After", InstantiatedPrepareAppUnitName(appName)))
	opts = append(opts, unit.NewUnitOption("Unit", "Requires", "sysusers.service"))
	opts = append(opts, unit.NewUnitOption("Unit", "After", "sysusers.service"))

	uw.WriteUnit(ServiceUnitPath(uw.p.Root, appName), "failed to create service unit file", opts...)
	uw.Activate(ServiceUnitName(appName), ServiceWantPath(uw.p.Root, appName))
}

// AppReaperUnit writes an app reaper service unit for the given app in the given path using the given unit options.
func (uw *UnitWriter) AppReaperUnit(appName types.ACName, binPath string, opts ...*unit.UnitOption) {
	if uw.err != nil {
		return
	}

	opts = append(opts, []*unit.UnitOption{
		unit.NewUnitOption("Unit", "Description", fmt.Sprintf("%s Reaper", appName)),
		unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
		unit.NewUnitOption("Unit", "StopWhenUnneeded", "yes"),
		unit.NewUnitOption("Unit", "Before", "halt.target"),
		unit.NewUnitOption("Unit", "Conflicts", "exit.target"),
		unit.NewUnitOption("Unit", "Conflicts", "halt.target"),
		unit.NewUnitOption("Unit", "Conflicts", "poweroff.target"),
		unit.NewUnitOption("Service", "RemainAfterExit", "yes"),
		unit.NewUnitOption("Service", "ExecStop", fmt.Sprintf(
			"/reaper.sh \"%s\" \"%s\" \"%s\"",
			appName,
			common.RelAppRootfsPath(appName),
			binPath,
		)),
	}...)

	uw.WriteUnit(
		ServiceUnitPath(uw.p.Root, types.ACName(fmt.Sprintf("reaper-%s", appName))),
		fmt.Sprintf("failed to write app %q reaper service", appName),
		opts...,
	)
}
