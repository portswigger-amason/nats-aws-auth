package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCache_Get(t *testing.T) {
	tests := []struct {
		name         string
		namespace    string
		saName       string
		setupCache   func(*Cache)
		wantPubPerms []string
		wantSubPerms []string
		wantFound    bool
	}{
		{
			name:      "ServiceAccount exists with both pub and sub annotations",
			namespace: "hakawai",
			saName:    "hakawai-litellm-proxy",
			setupCache: func(c *Cache) {
				sa := &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "hakawai-litellm-proxy",
						Namespace: "hakawai",
						Annotations: map[string]string{
							"nats.io/allowed-pub-subjects": "platform.events.>, shared.metrics.*",
							"nats.io/allowed-sub-subjects": "platform.commands.*, shared.status",
						},
					},
				}
				c.Upsert(sa)
			},
			wantPubPerms: []string{"hakawai.>", "platform.events.>", "shared.metrics.*"},
			wantSubPerms: []string{"_INBOX.>", "_INBOX_hakawai_hakawai-litellm-proxy.>", "hakawai.>", "platform.commands.*", "shared.status"},
			wantFound:    true,
		},
		{
			name:      "ServiceAccount exists with only pub annotation",
			namespace: "default",
			saName:    "test-sa",
			setupCache: func(c *Cache) {
				sa := &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-sa",
						Namespace: "default",
						Annotations: map[string]string{
							"nats.io/allowed-pub-subjects": "external.>",
						},
					},
				}
				c.Upsert(sa)
			},
			wantPubPerms: []string{"default.>", "external.>"},
			wantSubPerms: []string{"_INBOX.>", "_INBOX_default_test-sa.>", "default.>"},
			wantFound:    true,
		},
		{
			name:      "ServiceAccount exists with no NATS annotations",
			namespace: "production",
			saName:    "minimal-sa",
			setupCache: func(c *Cache) {
				sa := &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "minimal-sa",
						Namespace: "production",
						Annotations: map[string]string{
							"unrelated.io/annotation": "value",
						},
					},
				}
				c.Upsert(sa)
			},
			wantPubPerms: []string{"production.>"},
			wantSubPerms: []string{"_INBOX.>", "_INBOX_production_minimal-sa.>", "production.>"},
			wantFound:    true,
		},
		{
			name:      "ServiceAccount does not exist",
			namespace: "missing",
			saName:    "nonexistent",
			setupCache: func(c *Cache) {
				// Don't add anything to cache
			},
			wantPubPerms: nil,
			wantSubPerms: nil,
			wantFound:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewCache()
			tt.setupCache(cache)

			pubPerms, subPerms, found := cache.Get(tt.namespace, tt.saName)

			if found != tt.wantFound {
				t.Errorf("Get() found = %v, want %v", found, tt.wantFound)
			}

			if !equalStringSlices(pubPerms, tt.wantPubPerms) {
				t.Errorf("Get() pubPerms = %v, want %v", pubPerms, tt.wantPubPerms)
			}

			if !equalStringSlices(subPerms, tt.wantSubPerms) {
				t.Errorf("Get() subPerms = %v, want %v", subPerms, tt.wantSubPerms)
			}
		})
	}
}

func TestCache_Upsert(t *testing.T) {
	cache := NewCache()

	sa1 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "default",
			Annotations: map[string]string{
				"nats.io/allowed-pub-subjects": "initial.>",
			},
		},
	}
	cache.Upsert(sa1)

	pubPerms, _, found := cache.Get("default", "test-sa")
	if !found {
		t.Fatal("Expected ServiceAccount to be in cache after upsert")
	}
	if !equalStringSlices(pubPerms, []string{"default.>", "initial.>"}) {
		t.Errorf("Initial pubPerms = %v, want [default.> initial.>]", pubPerms)
	}

	// Update with new annotations
	sa2 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "default",
			Annotations: map[string]string{
				"nats.io/allowed-pub-subjects": "updated.>, another.*",
			},
		},
	}
	cache.Upsert(sa2)

	pubPerms, _, found = cache.Get("default", "test-sa")
	if !found {
		t.Fatal("Expected ServiceAccount to still be in cache after update")
	}
	if !equalStringSlices(pubPerms, []string{"default.>", "updated.>", "another.*"}) {
		t.Errorf("Updated pubPerms = %v, want [default.> updated.> another.*]", pubPerms)
	}
}

func TestCache_Delete(t *testing.T) {
	cache := NewCache()

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "default",
			Annotations: map[string]string{
				"nats.io/allowed-pub-subjects": "test.>",
			},
		},
	}
	cache.Upsert(sa)

	_, _, found := cache.Get("default", "test-sa")
	if !found {
		t.Fatal("Expected ServiceAccount to be in cache after upsert")
	}

	cache.Delete("default", "test-sa")

	_, _, found = cache.Get("default", "test-sa")
	if found {
		t.Error("Expected ServiceAccount to be removed from cache after delete")
	}
}

func TestParseSubjects(t *testing.T) {
	tests := []struct {
		name         string
		annotation   string
		wantSubjects []string
		wantFiltered []string
	}{
		{
			name:         "Multiple subjects with whitespace",
			annotation:   "platform.events.>, shared.metrics.*",
			wantSubjects: []string{"platform.events.>", "shared.metrics.*"},
			wantFiltered: []string{},
		},
		{
			name:         "Single subject",
			annotation:   "platform.commands.*",
			wantSubjects: []string{"platform.commands.*"},
			wantFiltered: []string{},
		},
		{
			name:         "Empty annotation",
			annotation:   "",
			wantSubjects: []string{},
			wantFiltered: []string{},
		},
		{
			name:         "Trailing comma",
			annotation:   "a.>, b.*,",
			wantSubjects: []string{"a.>", "b.*"},
			wantFiltered: []string{},
		},
		{
			name:         "Filter _INBOX.> pattern",
			annotation:   "_INBOX.>, platform.events.>",
			wantSubjects: []string{"platform.events.>"},
			wantFiltered: []string{"_INBOX.>"},
		},
		{
			name:         "Filter _REPLY.> pattern",
			annotation:   "_REPLY.>, platform.events.>",
			wantSubjects: []string{"platform.events.>"},
			wantFiltered: []string{"_REPLY.>"},
		},
		{
			name:         "Filter multiple internal patterns",
			annotation:   "_INBOX.>, _REPLY.>, platform.events.>, _INBOX_custom.>",
			wantSubjects: []string{"platform.events.>"},
			wantFiltered: []string{"_INBOX.>", "_REPLY.>", "_INBOX_custom.>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSubjects, gotFiltered := parseSubjects(tt.annotation)
			if !equalStringSlices(gotSubjects, tt.wantSubjects) {
				t.Errorf("parseSubjects() subjects = %v, want %v", gotSubjects, tt.wantSubjects)
			}
			if !equalStringSlices(gotFiltered, tt.wantFiltered) {
				t.Errorf("parseSubjects() filtered = %v, want %v", gotFiltered, tt.wantFiltered)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
