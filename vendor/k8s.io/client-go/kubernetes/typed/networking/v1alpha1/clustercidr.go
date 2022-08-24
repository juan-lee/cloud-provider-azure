/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	json "encoding/json"
	"fmt"
	"time"

	v1alpha1 "k8s.io/api/networking/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	networkingv1alpha1 "k8s.io/client-go/applyconfigurations/networking/v1alpha1"
	scheme "k8s.io/client-go/kubernetes/scheme"
	rest "k8s.io/client-go/rest"
)

// ClusterCIDRsGetter has a method to return a ClusterCIDRInterface.
// A group's client should implement this interface.
type ClusterCIDRsGetter interface {
	ClusterCIDRs() ClusterCIDRInterface
}

// ClusterCIDRInterface has methods to work with ClusterCIDR resources.
type ClusterCIDRInterface interface {
	Create(ctx context.Context, clusterCIDR *v1alpha1.ClusterCIDR, opts v1.CreateOptions) (*v1alpha1.ClusterCIDR, error)
	Update(ctx context.Context, clusterCIDR *v1alpha1.ClusterCIDR, opts v1.UpdateOptions) (*v1alpha1.ClusterCIDR, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.ClusterCIDR, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.ClusterCIDRList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterCIDR, err error)
	Apply(ctx context.Context, clusterCIDR *networkingv1alpha1.ClusterCIDRApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.ClusterCIDR, err error)
	ClusterCIDRExpansion
}

// clusterCIDRs implements ClusterCIDRInterface
type clusterCIDRs struct {
	client rest.Interface
}

// newClusterCIDRs returns a ClusterCIDRs
func newClusterCIDRs(c *NetworkingV1alpha1Client) *clusterCIDRs {
	return &clusterCIDRs{
		client: c.RESTClient(),
	}
}

// Get takes name of the clusterCIDR, and returns the corresponding clusterCIDR object, and an error if there is any.
func (c *clusterCIDRs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ClusterCIDR, err error) {
	result = &v1alpha1.ClusterCIDR{}
	err = c.client.Get().
		Resource("clustercidrs").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ClusterCIDRs that match those selectors.
func (c *clusterCIDRs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ClusterCIDRList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ClusterCIDRList{}
	err = c.client.Get().
		Resource("clustercidrs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested clusterCIDRs.
func (c *clusterCIDRs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("clustercidrs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a clusterCIDR and creates it.  Returns the server's representation of the clusterCIDR, and an error, if there is any.
func (c *clusterCIDRs) Create(ctx context.Context, clusterCIDR *v1alpha1.ClusterCIDR, opts v1.CreateOptions) (result *v1alpha1.ClusterCIDR, err error) {
	result = &v1alpha1.ClusterCIDR{}
	err = c.client.Post().
		Resource("clustercidrs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterCIDR).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a clusterCIDR and updates it. Returns the server's representation of the clusterCIDR, and an error, if there is any.
func (c *clusterCIDRs) Update(ctx context.Context, clusterCIDR *v1alpha1.ClusterCIDR, opts v1.UpdateOptions) (result *v1alpha1.ClusterCIDR, err error) {
	result = &v1alpha1.ClusterCIDR{}
	err = c.client.Put().
		Resource("clustercidrs").
		Name(clusterCIDR.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterCIDR).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the clusterCIDR and deletes it. Returns an error if one occurs.
func (c *clusterCIDRs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("clustercidrs").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *clusterCIDRs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("clustercidrs").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched clusterCIDR.
func (c *clusterCIDRs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterCIDR, err error) {
	result = &v1alpha1.ClusterCIDR{}
	err = c.client.Patch(pt).
		Resource("clustercidrs").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied clusterCIDR.
func (c *clusterCIDRs) Apply(ctx context.Context, clusterCIDR *networkingv1alpha1.ClusterCIDRApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.ClusterCIDR, err error) {
	if clusterCIDR == nil {
		return nil, fmt.Errorf("clusterCIDR provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(clusterCIDR)
	if err != nil {
		return nil, err
	}
	name := clusterCIDR.Name
	if name == nil {
		return nil, fmt.Errorf("clusterCIDR.Name must be provided to Apply")
	}
	result = &v1alpha1.ClusterCIDR{}
	err = c.client.Patch(types.ApplyPatchType).
		Resource("clustercidrs").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
