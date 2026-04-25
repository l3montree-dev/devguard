package dependencyfirewall

// NPMDependencyProxyController handles npm dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type NPMDependencyProxyController struct {
	*DependencyProxyController
}

func NewNPMDependencyProxyController(controller *DependencyProxyController) *NPMDependencyProxyController {
	return &NPMDependencyProxyController{DependencyProxyController: controller}
}

// GoDependencyProxyController handles Go dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type GoDependencyProxyController struct {
	*DependencyProxyController
}

func NewGoDependencyProxyController(controller *DependencyProxyController) *GoDependencyProxyController {
	return &GoDependencyProxyController{DependencyProxyController: controller}
}

// PythonDependencyProxyController handles PyPI dependency proxy requests.
// It embeds DependencyProxyController to reuse shared helpers and state.
type PythonDependencyProxyController struct {
	*DependencyProxyController
}

func NewPythonDependencyProxyController(controller *DependencyProxyController) *PythonDependencyProxyController {
	return &PythonDependencyProxyController{DependencyProxyController: controller}
}
