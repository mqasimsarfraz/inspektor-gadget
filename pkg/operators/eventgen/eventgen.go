package eventgen

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	name = "eventgen"
)

type eventGenOperator struct{}

func (e eventGenOperator) Name() string {
	return name
}

func (e eventGenOperator) Init(params *params.Params) error {
	return nil
}

func (e eventGenOperator) GlobalParams() api.Params {
	return api.Params{
		{
			Key:         "eventgen-enable",
			Description: "Enable event generation",
		},
	}
}

func (e eventGenOperator) InstanceParams() api.Params {
	return nil
}

func (e eventGenOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	return eventGenOperatorInstance{}, nil
}

func (e eventGenOperator) Priority() int {
	return 0
}

type eventGenOperatorInstance struct{}

func (e eventGenOperatorInstance) Name() string {
	return name
}

func (e eventGenOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	gadgetCtx.Logger().Infof("Starting %s", name)
	return nil
}

func (e eventGenOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	gadgetCtx.Logger().Infof("Stopping %s", name)
	return nil
}

var EventGen = eventGenOperator{}
