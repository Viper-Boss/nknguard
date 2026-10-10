package nat

// RouterMappingStatus reports mapping availability separately from STUN's
// observations. A private upstream address is never advertised as public.
type RouterMappingStatus struct {
	State        string `json:"state"`
	Message      string `json:"message"`
	Endpoint     string `json:"endpoint,omitempty"`
	InternalPort int    `json:"internal_port,omitempty"`
}
