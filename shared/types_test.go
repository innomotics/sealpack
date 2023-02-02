package shared

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func Test_ContainerImage(t *testing.T) {
	reg := "cr.siemens.com"
	image := "mathias.haimerl/sealpack:latest"
	ci := ParseContainerImage(reg, image)
	assert.Equal(t,
		strings.Join(
			[]string{ContainerImagePrefix, ci.Registry, ci.Name + ":" + ci.Tag + OCISuffix},
			"/",
		),
		ci.ToFileName(),
	)
	assert.Equal(t, strings.Join(
		[]string{ci.Registry, ci.Name + ":" + ci.Tag},
		"/",
	),
		ci.String(),
	)
}
