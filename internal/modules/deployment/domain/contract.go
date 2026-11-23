package domain

// RuntimeContract is compiled into the executable, available without config,
// secrets, storage or network initialization. The operator inspects exact images.
type RuntimeContract struct {
	ConfigurationFormat uint32 `json:"configuration_format"`
	RuntimeProtocol     uint32 `json:"runtime_protocol"`
	BootFormat          uint32 `json:"boot_format"`
	SchemaMin           int64  `json:"schema_min"`
	SchemaMax           int64  `json:"schema_max"`
	RoleMin             int64  `json:"role_min"`
	RoleMax             int64  `json:"role_max"`
}

func CurrentRuntimeContract() RuntimeContract {
	return RuntimeContract{ConfigurationFormat: 2, RuntimeProtocol: 1, BootFormat: BootFormat, SchemaMin: 27, SchemaMax: 27, RoleMin: 6, RoleMax: 6}
}
