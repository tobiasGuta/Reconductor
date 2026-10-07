package exactsupervision

// DeploymentPolicy is immutable expected metadata, not evidence that a host
// has installed or enforced it. Future deployment must verify these expectations
// and exclusive start authority before asserting NoLaterCommands.
type DeploymentPolicy struct{}

func FixedDeploymentPolicy() DeploymentPolicy                    { return DeploymentPolicy{} }
func (DeploymentPolicy) Type() string                            { return "exec" }
func (DeploymentPolicy) ExitType() string                        { return "main" }
func (DeploymentPolicy) Restart() string                         { return "no" }
func (DeploymentPolicy) RemainAfterExit() bool                   { return false }
func (DeploymentPolicy) Delegate() bool                          { return false }
func (DeploymentPolicy) NotifyAccess() string                    { return "none" }
func (DeploymentPolicy) RestartForceExitStatusMustBeEmpty() bool { return true }
func (DeploymentPolicy) ReactivationMustBeExcluded() bool        { return true }

type ResourceMechanism string

const (
	MemoryMax       ResourceMechanism = "MemoryMax"
	MemorySwapMax   ResourceMechanism = "MemorySwapMax"
	TasksMax        ResourceMechanism = "TasksMax"
	CPUQuota        ResourceMechanism = "CPUQuota"
	RuntimeMaxSec   ResourceMechanism = "RuntimeMaxSec"
	TimeoutStartSec ResourceMechanism = "TimeoutStartSec"
	TimeoutStopSec  ResourceMechanism = "TimeoutStopSec"
	OOMPolicy       ResourceMechanism = "OOMPolicy"
)

// ResourceMechanisms returns a value copy. No numerical policy is chosen here.
func (DeploymentPolicy) ResourceMechanisms() [8]ResourceMechanism {
	return [8]ResourceMechanism{MemoryMax, MemorySwapMax, TasksMax, CPUQuota, RuntimeMaxSec, TimeoutStartSec, TimeoutStopSec, OOMPolicy}
}
