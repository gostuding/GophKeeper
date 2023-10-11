package agent

type Storager interface {
	Check() error
}

// Agent struct.
type Agent struct {
	Config  *Config  // configuration object.
	Storage Storager // interfaice for data storage
}

// NewAgent creates new agent object.
func NewAgent(c *Config) *Agent {
	agent := Agent{Config: c, Client: &client}
	return &agent
}
