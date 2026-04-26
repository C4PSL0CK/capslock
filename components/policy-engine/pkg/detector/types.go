package detector

// NamespaceConfig contains all security configuration extracted from a Kubernetes namespace
type NamespaceConfig struct {
	// Basic Information
	Name        string            `json:"name"`
	Environment string            `json:"environment"` // dev, staging, prod
	Labels      map[string]string `json:"labels"`
	
	// Pod Security Configuration
	PodSecurity PodSecurityConfig `json:"pod_security"`
	
	// RBAC Configuration
	RBAC RBACConfig `json:"rbac"`
	
	// Network Security Configuration
	Network NetworkConfig `json:"network"`
	
	// Secrets Management Configuration
	Secrets SecretsConfig `json:"secrets"`
	
	// Resource Management Configuration
	Resources ResourceConfig `json:"resources"`
	
	// Audit and Logging Configuration
	Audit AuditConfig `json:"audit"`
	
	// Compliance Requirements
	RequiredCompliance []string `json:"required_compliance"` // ["cis", "pci-dss"]
}

// PodSecurityConfig contains pod-level security settings
type PodSecurityConfig struct {
	// Pod Security Standard (restricted, baseline, privileged)
	Standard string `json:"standard"`
	
	// Privileged Containers
	AllowPrivileged bool `json:"allow_privileged"`
	
	// Host Access
	AllowHostNetwork bool `json:"allow_host_network"`
	AllowHostPID     bool `json:"allow_host_pid"`
	AllowHostIPC     bool `json:"allow_host_ipc"`
	AllowHostPorts   bool `json:"allow_host_ports"`
	
	// Host Path Mounts
	AllowHostPath     bool     `json:"allow_host_path"`
	AllowedHostPaths  []string `json:"allowed_host_paths,omitempty"`
	
	// Security Context
	SeccompProfile  string `json:"seccomp_profile"`  // RuntimeDefault, Localhost, Unconfined
	AppArmorProfile string `json:"apparmor_profile"` // runtime/default, localhost/*, unconfined
	
	RunAsNonRoot           bool `json:"run_as_non_root"`
	ReadOnlyRootFilesystem bool `json:"read_only_root_filesystem"`
	
	// Capabilities
	AllowedCapabilities []string `json:"allowed_capabilities"`
	DroppedCapabilities []string `json:"dropped_capabilities"`
	RequireDropAll      bool     `json:"require_drop_all"` // Must drop ALL capabilities
	
	// Privilege Escalation
	AllowPrivilegeEscalation bool `json:"allow_privilege_escalation"`
	
	// Resource Limits
	RequireResourceLimits bool `json:"require_resource_limits"`
	
	// Pod-level stats
	TotalPods              int `json:"total_pods"`
	PrivilegedPods         int `json:"privileged_pods"`
	HostNetworkPods        int `json:"host_network_pods"`
	PodsWithoutLimits      int `json:"pods_without_limits"`
	PodsRunningAsRoot      int `json:"pods_running_as_root"`
}

// RBACConfig contains RBAC-related security settings
type RBACConfig struct {
	// Service Accounts
	ServiceAccountAutoMount bool     `json:"service_account_auto_mount"`
	DefaultSAUsed           bool     `json:"default_sa_used"` // Are pods using default SA?
	TotalServiceAccounts    int      `json:"total_service_accounts"`
	ServiceAccountNames     []string `json:"service_account_names,omitempty"`
	
	// Role Bindings
	ClusterAdminBindings bool     `json:"cluster_admin_bindings"` // Any cluster-admin bindings?
	WildcardPermissions  bool     `json:"wildcard_permissions"`   // Any wildcard (*) permissions?
	TotalRoleBindings    int      `json:"total_role_bindings"`
	
	// Secrets Access
	SecretsAccessCount int      `json:"secrets_access_count"` // How many roles can access secrets?
	SecretsAccessRoles []string `json:"secrets_access_roles,omitempty"`
	
	// Specific dangerous permissions
	HasClusterAdminRole   bool `json:"has_cluster_admin_role"`
	HasWildcardRoles      bool `json:"has_wildcard_roles"`
	HasSecretsReadAccess  bool `json:"has_secrets_read_access"`
	HasSecretsWriteAccess bool `json:"has_secrets_write_access"`
}

// NetworkConfig contains network security settings
type NetworkConfig struct {
	// Network Policies
	NetworkPoliciesExist bool `json:"network_policies_exist"`
	TotalNetworkPolicies int  `json:"total_network_policies"`
	
	// Default Deny Policies
	DefaultDenyIngress bool `json:"default_deny_ingress"`
	DefaultDenyEgress  bool `json:"default_deny_egress"`
	
	// CNI Plugin
	CNIPlugin         string `json:"cni_plugin"`          // calico, cilium, flannel, etc.
	CNISupportsPolicy bool   `json:"cni_supports_policy"` // Does CNI support NetworkPolicy?
	
	// Network Policy Details
	IngressRulesCount int `json:"ingress_rules_count"`
	EgressRulesCount  int `json:"egress_rules_count"`
}

// SecretsConfig contains secrets management settings
type SecretsConfig struct {
	// Total secrets in namespace
	TotalSecrets int `json:"total_secrets"`
	
	// Secret Types
	OpaqueSecrets        int `json:"opaque_secrets"`
	TLSSecrets           int `json:"tls_secrets"`
	DockerConfigSecrets  int `json:"docker_config_secrets"`
	ServiceAccountTokens int `json:"service_account_tokens"`
	
	// Usage Patterns
	SecretsAsEnvVars     bool `json:"secrets_as_env_vars"`      // Are secrets mounted as env vars?
	SecretsAsVolumes     bool `json:"secrets_as_volumes"`       // Are secrets mounted as volumes?
	PodsWithSecretsAsEnv int  `json:"pods_with_secrets_as_env"` // Count of pods using env vars
	
	// External Secrets Manager
	ExternalSecretsManager     bool   `json:"external_secrets_manager"`      // Using ESO, Vault, etc.?
	ExternalSecretsManagerType string `json:"external_secrets_manager_type"` // "vault", "eso", etc.
	
	// Encryption at Rest (cluster-level, but tracked here)
	EncryptionAtRest        bool   `json:"encryption_at_rest"`
	EncryptionProvider      string `json:"encryption_provider,omitempty"` // aescbc, kms, etc.
}

// ResourceConfig contains resource quota and limit settings
type ResourceConfig struct {
	// Resource Quotas
	ResourceQuotaExists bool `json:"resource_quota_exists"`
	TotalResourceQuotas int  `json:"total_resource_quotas"`
	
	// Resource Quota Details
	CPUQuota    string `json:"cpu_quota,omitempty"`    // e.g., "10" cores
	MemoryQuota string `json:"memory_quota,omitempty"` // e.g., "20Gi"
	PodsQuota   string `json:"pods_quota,omitempty"`   // e.g., "50"
	
	// Limit Ranges
	LimitRangeExists bool `json:"limit_range_exists"`
	TotalLimitRanges int  `json:"total_limit_ranges"`
	
	// Limit Range Details
	DefaultCPULimit    string `json:"default_cpu_limit,omitempty"`
	DefaultMemoryLimit string `json:"default_memory_limit,omitempty"`
	MinCPU             string `json:"min_cpu,omitempty"`
	MaxCPU             string `json:"max_cpu,omitempty"`
	MinMemory          string `json:"min_memory,omitempty"`
	MaxMemory          string `json:"max_memory,omitempty"`
	
	// Usage Statistics
	PodsWithCPULimits    int `json:"pods_with_cpu_limits"`
	PodsWithMemoryLimits int `json:"pods_with_memory_limits"`
	PodsWithoutLimits    int `json:"pods_without_limits"`
}

// AuditConfig contains audit and logging settings
type AuditConfig struct {
	// Audit Policy (cluster-level, but relevant for compliance)
	AuditPolicyExists bool   `json:"audit_policy_exists"`
	AuditBackend      string `json:"audit_backend,omitempty"` // log, webhook, dynamic
	
	// Audit Log Settings
	AuditLogEnabled    bool   `json:"audit_log_enabled"`
	AuditLogPath       string `json:"audit_log_path,omitempty"`
	AuditLogMaxAge     int    `json:"audit_log_max_age,omitempty"`     // days
	AuditLogMaxBackup  int    `json:"audit_log_max_backup,omitempty"`  // count
	AuditLogMaxSize    int    `json:"audit_log_max_size,omitempty"`    // MB
	
	// Audit Levels
	AuditLevel string `json:"audit_level,omitempty"` // None, Metadata, Request, RequestResponse
}

// Helper function to create empty NamespaceConfig
func NewNamespaceConfig(name string) *NamespaceConfig {
	return &NamespaceConfig{
		Name:   name,
		Labels: make(map[string]string),
		PodSecurity: PodSecurityConfig{
			AllowedCapabilities: []string{},
			DroppedCapabilities: []string{},
		},
		RBAC: RBACConfig{
			ServiceAccountNames: []string{},
			SecretsAccessRoles:  []string{},
		},
		Network: NetworkConfig{},
		Secrets: SecretsConfig{},
		Resources: ResourceConfig{},
		Audit: AuditConfig{},
		RequiredCompliance: []string{},
	}
}

// IsDefaultNamespace checks if this is the default namespace (CIS 4.5.1)
func (nc *NamespaceConfig) IsDefaultNamespace() bool {
	return nc.Name == "default"
}

// HasPrivilegedContainers checks if namespace allows privileged containers (CIS 4.2.1)
func (nc *NamespaceConfig) HasPrivilegedContainers() bool {
	return nc.PodSecurity.AllowPrivileged || nc.PodSecurity.PrivilegedPods > 0
}

// HasNetworkPolicies checks if namespace has network policies defined (CIS 4.3.2)
func (nc *NamespaceConfig) HasNetworkPolicies() bool {
	return nc.Network.NetworkPoliciesExist && nc.Network.TotalNetworkPolicies > 0
}

// HasDefaultDenyPolicy checks if default deny policies exist (CIS 4.3.3)
func (nc *NamespaceConfig) HasDefaultDenyPolicy() bool {
	return nc.Network.DefaultDenyIngress && nc.Network.DefaultDenyEgress
}

// HasResourceQuota checks if namespace has resource quota (CIS 4.5.2)
func (nc *NamespaceConfig) HasResourceQuota() bool {
	return nc.Resources.ResourceQuotaExists
}

// HasLimitRange checks if namespace has limit range (CIS 4.5.3)
func (nc *NamespaceConfig) HasLimitRange() bool {
	return nc.Resources.LimitRangeExists
}

// UsesSecretsAsEnvVars checks if secrets are used as environment variables (CIS 4.4.1)
func (nc *NamespaceConfig) UsesSecretsAsEnvVars() bool {
	return nc.Secrets.SecretsAsEnvVars
}

// HasExternalSecretsManager checks if external secrets manager is used (CIS 4.4.2)
func (nc *NamespaceConfig) HasExternalSecretsManager() bool {
	return nc.Secrets.ExternalSecretsManager
}