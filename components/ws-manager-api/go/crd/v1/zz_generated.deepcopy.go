//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// Copyright (c) 2022 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

// Code generated by controller-gen. DO NOT EDIT.

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AdmissionSpec) DeepCopyInto(out *AdmissionSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AdmissionSpec.
func (in *AdmissionSpec) DeepCopy() *AdmissionSpec {
	if in == nil {
		return nil
	}
	out := new(AdmissionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitSpec) DeepCopyInto(out *GitSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitSpec.
func (in *GitSpec) DeepCopy() *GitSpec {
	if in == nil {
		return nil
	}
	out := new(GitSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitStatus) DeepCopyInto(out *GitStatus) {
	*out = *in
	if in.UncommitedFiles != nil {
		in, out := &in.UncommitedFiles, &out.UncommitedFiles
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.UntrackedFiles != nil {
		in, out := &in.UntrackedFiles, &out.UntrackedFiles
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.UnpushedCommits != nil {
		in, out := &in.UnpushedCommits, &out.UnpushedCommits
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitStatus.
func (in *GitStatus) DeepCopy() *GitStatus {
	if in == nil {
		return nil
	}
	out := new(GitStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IDEImages) DeepCopyInto(out *IDEImages) {
	*out = *in
	if in.Refs != nil {
		in, out := &in.Refs, &out.Refs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IDEImages.
func (in *IDEImages) DeepCopy() *IDEImages {
	if in == nil {
		return nil
	}
	out := new(IDEImages)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Ownership) DeepCopyInto(out *Ownership) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Ownership.
func (in *Ownership) DeepCopy() *Ownership {
	if in == nil {
		return nil
	}
	out := new(Ownership)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PortSpec) DeepCopyInto(out *PortSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PortSpec.
func (in *PortSpec) DeepCopy() *PortSpec {
	if in == nil {
		return nil
	}
	out := new(PortSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TimeoutSpec) DeepCopyInto(out *TimeoutSpec) {
	*out = *in
	if in.Time != nil {
		in, out := &in.Time, &out.Time
		*out = new(metav1.Duration)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TimeoutSpec.
func (in *TimeoutSpec) DeepCopy() *TimeoutSpec {
	if in == nil {
		return nil
	}
	out := new(TimeoutSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Workspace) DeepCopyInto(out *Workspace) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Workspace.
func (in *Workspace) DeepCopy() *Workspace {
	if in == nil {
		return nil
	}
	out := new(Workspace)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Workspace) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceConditions) DeepCopyInto(out *WorkspaceConditions) {
	*out = *in
	if in.FirstUserActivity != nil {
		in, out := &in.FirstUserActivity, &out.FirstUserActivity
		*out = (*in).DeepCopy()
	}
	if in.StoppedByRequest != nil {
		in, out := &in.StoppedByRequest, &out.StoppedByRequest
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceConditions.
func (in *WorkspaceConditions) DeepCopy() *WorkspaceConditions {
	if in == nil {
		return nil
	}
	out := new(WorkspaceConditions)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceImage) DeepCopyInto(out *WorkspaceImage) {
	*out = *in
	if in.Ref != nil {
		in, out := &in.Ref, &out.Ref
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceImage.
func (in *WorkspaceImage) DeepCopy() *WorkspaceImage {
	if in == nil {
		return nil
	}
	out := new(WorkspaceImage)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceImages) DeepCopyInto(out *WorkspaceImages) {
	*out = *in
	in.Workspace.DeepCopyInto(&out.Workspace)
	in.IDE.DeepCopyInto(&out.IDE)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceImages.
func (in *WorkspaceImages) DeepCopy() *WorkspaceImages {
	if in == nil {
		return nil
	}
	out := new(WorkspaceImages)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceList) DeepCopyInto(out *WorkspaceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Workspace, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceList.
func (in *WorkspaceList) DeepCopy() *WorkspaceList {
	if in == nil {
		return nil
	}
	out := new(WorkspaceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *WorkspaceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceRuntimeStatus) DeepCopyInto(out *WorkspaceRuntimeStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceRuntimeStatus.
func (in *WorkspaceRuntimeStatus) DeepCopy() *WorkspaceRuntimeStatus {
	if in == nil {
		return nil
	}
	out := new(WorkspaceRuntimeStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceSpec) DeepCopyInto(out *WorkspaceSpec) {
	*out = *in
	out.Ownership = in.Ownership
	in.Image.DeepCopyInto(&out.Image)
	if in.Initializer != nil {
		in, out := &in.Initializer, &out.Initializer
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	if in.Envvars != nil {
		in, out := &in.Envvars, &out.Envvars
		*out = make([]corev1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Git != nil {
		in, out := &in.Git, &out.Git
		*out = new(GitSpec)
		**out = **in
	}
	in.Timeout.DeepCopyInto(&out.Timeout)
	out.Admission = in.Admission
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make([]PortSpec, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceSpec.
func (in *WorkspaceSpec) DeepCopy() *WorkspaceSpec {
	if in == nil {
		return nil
	}
	out := new(WorkspaceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WorkspaceStatus) DeepCopyInto(out *WorkspaceStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.GitStatus != nil {
		in, out := &in.GitStatus, &out.GitStatus
		*out = new(GitStatus)
		(*in).DeepCopyInto(*out)
	}
	if in.Runtime != nil {
		in, out := &in.Runtime, &out.Runtime
		*out = new(WorkspaceRuntimeStatus)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WorkspaceStatus.
func (in *WorkspaceStatus) DeepCopy() *WorkspaceStatus {
	if in == nil {
		return nil
	}
	out := new(WorkspaceStatus)
	in.DeepCopyInto(out)
	return out
}
