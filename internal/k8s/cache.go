// Package k8s provides Kubernetes ServiceAccount caching and client functionality.
package k8s

import (
	"fmt"
	"log"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

const (
	// AnnotationAllowedPubSubjects is the annotation key for allowed NATS publish subjects.
	AnnotationAllowedPubSubjects = "nats.io/allowed-pub-subjects"
	// AnnotationAllowedSubSubjects is the annotation key for allowed NATS subscribe subjects.
	AnnotationAllowedSubSubjects = "nats.io/allowed-sub-subjects"
)

// Permissions represents the NATS publish and subscribe permissions for a ServiceAccount.
type Permissions struct {
	Publish   []string
	Subscribe []string
}

// Cache is a thread-safe in-memory cache of ServiceAccount permissions.
type Cache struct {
	mu    sync.RWMutex
	cache map[string]*Permissions // key: "namespace/name"
}

// NewCache creates a new empty ServiceAccount cache.
func NewCache() *Cache {
	return &Cache{
		cache: make(map[string]*Permissions),
	}
}

// Get retrieves the permissions for a ServiceAccount by namespace and name.
func (c *Cache) Get(namespace, name string) (pubPerms, subPerms []string, found bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := makeKey(namespace, name)
	perms, found := c.cache[key]
	if !found {
		return nil, nil, false
	}

	return perms.Publish, perms.Subscribe, true
}

// Upsert adds or updates a ServiceAccount in the cache.
func (c *Cache) Upsert(sa *corev1.ServiceAccount) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := makeKey(sa.Namespace, sa.Name)
	perms := buildPermissions(sa)
	c.cache[key] = perms
}

// Delete removes a ServiceAccount from the cache.
func (c *Cache) Delete(namespace, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := makeKey(namespace, name)
	delete(c.cache, key)
}

// buildPermissions constructs NATS permissions from a ServiceAccount's annotations.
func buildPermissions(sa *corev1.ServiceAccount) *Permissions {
	perms := &Permissions{}

	// Default: namespace scope
	defaultSubject := fmt.Sprintf("%s.>", sa.Namespace)
	perms.Publish = []string{defaultSubject}

	// Subscribe: inbox patterns + namespace scope
	privateInbox := fmt.Sprintf("_INBOX_%s_%s.>", sa.Namespace, sa.Name)
	perms.Subscribe = []string{"_INBOX.>", privateInbox, defaultSubject}

	// Additional subjects from annotations
	if pubAnnotation, ok := sa.Annotations[AnnotationAllowedPubSubjects]; ok {
		additionalPub, filteredPub := parseSubjects(pubAnnotation)
		if len(filteredPub) > 0 {
			log.Printf("WARNING: Filtered NATS internal subjects from %s/%s annotation %s: %v",
				sa.Namespace, sa.Name, AnnotationAllowedPubSubjects, filteredPub)
		}
		perms.Publish = append(perms.Publish, additionalPub...)
	}

	if subAnnotation, ok := sa.Annotations[AnnotationAllowedSubSubjects]; ok {
		additionalSub, filteredSub := parseSubjects(subAnnotation)
		if len(filteredSub) > 0 {
			log.Printf("WARNING: Filtered NATS internal subjects from %s/%s annotation %s: %v",
				sa.Namespace, sa.Name, AnnotationAllowedSubSubjects, filteredSub)
		}
		perms.Subscribe = append(perms.Subscribe, additionalSub...)
	}

	return perms
}

// parseSubjects parses a comma-separated list of NATS subjects from an annotation value.
// Filters out _INBOX and _REPLY patterns as those are automatically managed by NATS.
func parseSubjects(annotation string) (subjects, filtered []string) {
	if annotation == "" {
		return []string{}, []string{}
	}

	parts := strings.Split(annotation, ",")
	subjects = make([]string, 0, len(parts))
	filtered = make([]string, 0)

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "_INBOX") || strings.HasPrefix(trimmed, "_REPLY") {
			filtered = append(filtered, trimmed)
			continue
		}

		subjects = append(subjects, trimmed)
	}

	return subjects, filtered
}

func makeKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}
