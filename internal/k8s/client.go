package k8s

import (
	"context"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// Client manages Kubernetes ServiceAccount watching and caching.
type Client struct {
	cache    *Cache
	informer cache.SharedIndexInformer
	stopCh   chan struct{}
}

// NewClient creates a new Kubernetes client with ServiceAccount informer.
func NewClient(factory informers.SharedInformerFactory) *Client {
	saCache := NewCache()

	informer := factory.Core().V1().ServiceAccounts().Informer()

	client := &Client{
		cache:    saCache,
		informer: informer,
		stopCh:   make(chan struct{}),
	}

	_, err := informer.AddEventHandler(&cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			sa, ok := obj.(*corev1.ServiceAccount)
			if !ok {
				runtime.HandleError(fmt.Errorf("unexpected object type: %T", obj))
				return
			}
			client.cache.Upsert(sa)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			sa, ok := newObj.(*corev1.ServiceAccount)
			if !ok {
				runtime.HandleError(fmt.Errorf("unexpected object type: %T", newObj))
				return
			}
			client.cache.Upsert(sa)
		},
		DeleteFunc: func(obj interface{}) {
			sa, ok := obj.(*corev1.ServiceAccount)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					runtime.HandleError(fmt.Errorf("unexpected object type: %T", obj))
					return
				}
				sa, ok = tombstone.Obj.(*corev1.ServiceAccount)
				if !ok {
					runtime.HandleError(fmt.Errorf("tombstone contained unexpected object: %T", tombstone.Obj))
					return
				}
			}
			client.cache.Delete(sa.Namespace, sa.Name)
		},
	})

	if err != nil {
		runtime.HandleError(fmt.Errorf("failed to add event handler: %w", err))
	}

	return client
}

// Start begins the informer and waits for cache sync.
func (c *Client) Start(ctx context.Context) {
	go c.informer.Run(c.stopCh)

	log.Println("Waiting for K8s ServiceAccount informer cache to sync...")
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		log.Println("WARNING: failed to sync K8s informer cache")
	}
	log.Println("K8s ServiceAccount informer cache synced")
}

// GetPermissions retrieves the NATS permissions for a ServiceAccount.
func (c *Client) GetPermissions(namespace, name string) (pubPerms, subPerms []string, found bool) {
	return c.cache.Get(namespace, name)
}

// Shutdown gracefully shuts down the client.
func (c *Client) Shutdown() {
	close(c.stopCh)
}
