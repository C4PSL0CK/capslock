package pcidss

// PCIDSSRequirement is now defined in types.go

// GetAllPCIDSSRequirements returns all PCI-DSS requirements applicable to Kubernetes
func GetAllPCIDSSRequirements() []PCIDSSRequirement {
	return []PCIDSSRequirement{
		// Requirement 1: Install and maintain network security controls
		{
			ID:                "1.2.1",
			ParentRequirement: "1",
			Title:             "Network security controls are configured and maintained",
			// ... rest of the requirement
		},
		// ... all 16 requirements
	}
}