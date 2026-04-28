package scanner

import "testing"

func TestGetContainersSupportsCommonWorkloads(t *testing.T) {
	s := &Scanner{}

	tests := []struct {
		name           string
		resource       K8sResource
		wantContainers int
	}{
		{
			name: "pod",
			resource: K8sResource{
				Kind: "Pod",
				Spec: map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{"name": "app"},
					},
				},
			},
			wantContainers: 1,
		},
		{
			name: "deployment",
			resource: K8sResource{
				Kind: "Deployment",
				Spec: map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{"name": "app"},
							},
						},
					},
				},
			},
			wantContainers: 1,
		},
		{
			name: "daemonset",
			resource: K8sResource{
				Kind: "DaemonSet",
				Spec: map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{"name": "app"},
							},
						},
					},
				},
			},
			wantContainers: 1,
		},
		{
			name: "statefulset",
			resource: K8sResource{
				Kind: "StatefulSet",
				Spec: map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{"name": "app"},
							},
						},
					},
				},
			},
			wantContainers: 1,
		},
		{
			name: "job",
			resource: K8sResource{
				Kind: "Job",
				Spec: map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{"name": "app"},
							},
						},
					},
				},
			},
			wantContainers: 1,
		},
		{
			name: "cronjob",
			resource: K8sResource{
				Kind: "CronJob",
				Spec: map[string]interface{}{
					"jobTemplate": map[string]interface{}{
						"spec": map[string]interface{}{
							"template": map[string]interface{}{
								"spec": map[string]interface{}{
									"containers": []interface{}{
										map[string]interface{}{"name": "app"},
									},
								},
							},
						},
					},
				},
			},
			wantContainers: 1,
		},
		{
			name: "replicaset with init container",
			resource: K8sResource{
				Kind: "ReplicaSet",
				Spec: map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{
								map[string]interface{}{"name": "app"},
							},
							"initContainers": []interface{}{
								map[string]interface{}{"name": "init"},
							},
						},
					},
				},
			},
			wantContainers: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			containers := s.getContainers(test.resource)
			if len(containers) != test.wantContainers {
				t.Fatalf("expected %d containers, got %d", test.wantContainers, len(containers))
			}
		})
	}
}
