package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/argoproj/argo-cd/v2/cmd/argocd-application-controller/commands"
	"github.com/spf13/pflag"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"io"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

func main() {
	manifests, err := buildKustomization("test/manifests/base")
	if err != nil {
		panic(fmt.Sprintf("could not generate manifests from kustomization, %s", err))
	}

	unstructureds, err := decodeYAMLToUnstructured(manifests)
	if err != nil {
		panic(fmt.Sprintf("could not convert to unstructureds, %s", err))
	}

	ctx := context.Background()

	k3sContainer, err := k3s.RunContainer(ctx,
		testcontainers.WithImage("rancher/k3s:v1.27.1-k3s1"))
	if err != nil {
		panic(fmt.Sprintf("could not start k3s, %s", err))
	}

	kubeConfigYaml, err := k3sContainer.GetKubeConfig(ctx)
	if err != nil {
		panic(fmt.Sprintf("could not get k3s kubeconfig, %s", err))
	}

	config, err := clientcmd.RESTConfigFromKubeConfig(kubeConfigYaml)
	if err != nil {
		panic(fmt.Sprintf("could not get k3s rest config, %s", err))
	}

	// Create a Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(fmt.Sprintf("error creating Kubernetes client: %s", err))
	}

	// Define the namespace details
	namespace := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "argocd",
		},
	}

	_, err = clientset.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("could not create namespace, %s", err))
	}

	redisContainer, err := redis.RunContainer(ctx, testcontainers.WithImage("redis:6"))
	if err != nil {
		panic(fmt.Sprintf("could not create redis, %s", err))
	}

	endpoint, err := redisContainer.Endpoint(ctx, "")
	if err != nil {
		panic(fmt.Sprintf("could not get redis endpoint, %s", err))
	}

	println(endpoint)

	flags := pflag.NewFlagSet("", pflag.PanicOnError)
	appcontrollerConfig := commands.NewApplicationControllerConfig(flags, flags).WithDefaultFlags().WithK8sSettings(namespace.Name, config)

	err = flags.Set("redis", endpoint)
	if err != nil {
		panic(fmt.Sprintf("cannot set redis endpoint, %s", err))
	}

	err = flags.Parse([]string{})
	if err != nil {
		panic(fmt.Sprintf("app controller flags fail, %s", err))
	}

	err = appcontrollerConfig.CreateApplicationController(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to create app controller, %s", err))
	}

	err = applyManifests(config, unstructureds)
	if err != nil {
		panic(fmt.Sprintf("noooooo, %s", err))
	}
}

func applyManifests(config *rest.Config, unstructureds []*unstructured.Unstructured) error {
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}

	// Create a DiscoveryClient
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return err
	}

	resources, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		return err
	}

	for _, u := range unstructureds {
		gvk := u.GroupVersionKind()

		// Use DiscoveryClient to find if the resource is namespaced
		resList, err := discoveryClient.ServerResourcesForGroupVersion(gvk.GroupVersion().String())

		ns := ""

		for _, res := range resList.APIResources {
			if res.Kind == gvk.Kind {
				if res.Namespaced {
					ns = "argocd"
				}
				break
			}
		}

		for _, list := range resources {
			for _, res := range list.APIResources {
				if res.Kind == gvk.Kind {
					gvr := schema.GroupVersionResource{Group: gvk.Group, Version: gvk.Version, Resource: res.Name}
					_, err := dynamicClient.Resource(gvr).Namespace(ns).Create(context.TODO(), u, metav1.CreateOptions{})
					if err != nil {
						return err
					}

					break
				}
			}
		}

		if err != nil {
			return fmt.Errorf("could not create %s: %s", u.GetName(), err)
		}
	}

	return nil
}

func buildKustomization(overlayPath string) ([]byte, error) {
	// Setup the file system to use with the Kustomize API
	fs := filesys.MakeFsOnDisk()

	// Configuration options for Kustomize build
	opts := &krusty.Options{
		LoadRestrictions: types.LoadRestrictionsNone,
		PluginConfig:     types.DisabledPluginConfig(),
	}

	// Create a Kustomize Build instance
	kustomizer := krusty.MakeKustomizer(opts)

	// Perform the build
	resMap, err := kustomizer.Run(fs, overlayPath)
	if err != nil {
		return nil, err
	}

	resMap.Resources()
	// Convert the resource map to a YAML string
	yml, err := resMap.AsYaml()
	if err != nil {
		return nil, err
	}

	return yml, nil
}

func decodeYAMLToUnstructured(yamlBytes []byte) ([]*unstructured.Unstructured, error) {
	var unstructs []*unstructured.Unstructured

	dec := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(yamlBytes), 1024)
	for {
		var obj unstructured.Unstructured
		if err := dec.Decode(&obj); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		unstructs = append(unstructs, &obj)
	}
	return unstructs, nil
}
