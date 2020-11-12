import React, {Component} from 'react';
import {Modal} from "react-bootstrap";
import Form from "react-jsonschema-form";
import PropTypes from 'prop-types';

class SubscriberModal extends Component {
  static propTypes = {
    open: PropTypes.bool.isRequired,
    setOpen: PropTypes.func.isRequired,
    subscriber: PropTypes.object,
    onModify: PropTypes.func.isRequired,
    onSubmit: PropTypes.func.isRequired,
  };

  state = {
    editMode: false,
    formData: undefined,
    // for force re-rendering json form
    rerenderCounter: 0,
  };

  state = {
    formData: undefined,
    editMode: false,
    // for force re-rendering json form
    rerenderCounter: 0,
  };

  schema = {
    // title: "A registration form",
    // "description": "A simple form example.",
    type: "object",
    required: [
      "plmnID",
      "ueId",
      "authenticationMethod",
      "K",
      "OPOPcSelect",
      "OPOPc",
    ],
    properties: {
      plmnID: {
        type: "string",
        title: "PLMN ID",
        default: "20893",
      },
      ueId: {
        type: "string",
        title: "SUPI (IMSI)",
        default: "208930000000003",
      },
      authenticationMethod: {
        type: "string",
        title: "Authentication Method",
        default: "5G_AKA",
        enum: ["5G_AKA", "EAP_AKA_PRIME"],
      },
      K: {
        type: "string",
        title: "K",
        default: "8baf473f2f8fd09487cccbd7097c6862",
      },
      OPOPcSelect: {
        type: "string",
        title: "Operator Code Type",
        enum: ["OP", "OPc"],
        default: "OPc",
      },
      OPOPc: {
        type: "string",
        title: "Operator Code Value",
        default: "8e27b6af0e692e750f32667a3b14605d",
      },
      defaultSingleNssais: {
        type: "array",
        title: "NSSAI - Default",
        items: {
          type: "object",
          required: [
            "sd",
            "sst",
          ],
          properties: {
            "sst": {
              "type": "integer",
              "title": "SST",
            },
            "sd": {
              "type": "string",
              "title": "SD",
            },
          }
        },
        default: [
          {
            "sst": 1,
            "sd": "010203",
          },
          {
            "sst": 1,
            "sd": "112233",
          },
        ],
      },
      singleNssais: {
        type: "array",
        title: "NSSAI - Single",
        items: {
          type: "object",
          required: ["sst", "sd"],
          properties: {
            "sst": {
              "type": "integer",
              "title": "SST",
            },
            "sd": {
              "type": "string",
              "title": "SD",
            },
          }
        },
        default: [
          {
            "sst": 1,
            "sd": "010203",
          },
          {
            "sst": 1,
            "sd": "112233",
          },
        ],
      },
    }
  };

  uiSchema = {
    OPOPcSelect: {
      "ui:widget": "select",
    },
    authenticationMethod: {
      "ui:widget": "select",
    },

    defaultSingleNssais:{
            "ui:options": {
              "orderable": false
          }
        },

        singleNssais:{
          "ui:options": {
            "orderable": false
        }
      }
  };

  componentDidUpdate(prevProps, prevState, snapshot) {
    if (prevProps !== this.props) {
      this.setState({editMode: !!this.props.subscriber});

      if (this.props.subscriber) {
        const subscriber = this.props.subscriber;
        const isOp = subscriber['AuthenticationSubscription']["milenage"]["op"]["opValue"] !== "";

        let formData = {
          plmnID: subscriber['plmnID'],
          ueId: subscriber['ueId'].replace("imsi-", ""),
          authenticationMethod: subscriber['AuthenticationSubscription']["authenticationMethod"],
          K: subscriber['AuthenticationSubscription']["permanentKey"]["permanentKeyValue"],
          OPOPcSelect: isOp ? "OP" : "OPc",
          OPOPc: isOp ? subscriber['AuthenticationSubscription']["milenage"]["op"]["opValue"] :
                        subscriber['AuthenticationSubscription']["opc"]["opcValue"],
        };

        this.updateFormData(formData).then();
      }
    }
  }

  async onChange(data) {
    const lastData = this.state.formData;
    const newData = data.formData;

    if (lastData && lastData.plmnID === undefined)
      lastData.plmnID = "";

    if (lastData && lastData.plmnID !== newData.plmnID &&
      newData.ueId.length === lastData.plmnID.length + "0000000003".length) {
      const plmn = newData.plmnID ? newData.plmnID : "";
      newData.ueId = plmn + newData.ueId.substr(lastData.plmnID.length);

      await this.updateFormData(newData);

      // Keep plmnID input focused at the end
      const plmnInput = document.getElementById("root_plmnID");
      plmnInput.selectionStart = plmnInput.selectionEnd = plmnInput.value.length;
      plmnInput.focus();
    } else {
      this.setState({
        formData: newData,
      });
    }
  }

  async updateFormData(newData) {
    // Workaround for bug: https://github.com/rjsf-team/react-jsonschema-form/issues/758
    await this.setState({ rerenderCounter: this.state.rerenderCounter + 1 });
    await this.setState({
      rerenderCounter: this.state.rerenderCounter + 1,
      formData: newData,
    });
  }

  onSubmitClick(result) {
    const formData = result.formData;
    const OP = formData["OPOPcSelect"] === "OP" ? formData["OPOPc"] : "";
    const OPc = formData["OPOPcSelect"] === "OPc" ? formData["OPOPc"] : "";

    let subscriberData = {
      "plmnID": formData["plmnID"], // Change required
      "ueId": "imsi-" + formData["ueId"], // Change required
      "AuthenticationSubscription": {
        "authenticationManagementField": "8000",
        "authenticationMethod": formData["authenticationMethod"], // "5G_AKA", "EAP_AKA_PRIME"
        "milenage": {
          "op": {
            "encryptionAlgorithm": 0,
            "encryptionKey": 0,
            "opValue": OP // Change required
          }
        },
        "opc": {
          "encryptionAlgorithm": 0,
          "encryptionKey": 0,
          "opcValue": OPc // Change required (one of OPc/OP should be filled)
        },
        "permanentKey": {
          "encryptionAlgorithm": 0,
          "encryptionKey": 0,
          "permanentKeyValue": formData["K"] // Change required
        },
        "sequenceNumber": "16f3b3f70fc2",
      },
      "AccessAndMobilitySubscriptionData": {
        "gpsis": [
          "msisdn-0900000000"
        ],
        "nssai": {
          "defaultSingleNssais": [
            {
              "sd": "010203",
              "sst": 1
            },
            {
              "sd": "112233",
              "sst": 1
            }
          ],
          "singleNssais": [
            {
              "sd": "010203",
              "sst": 1
            },
            {
              "sd": "112233",
              "sst": 1
            }
          ]
        },
        "subscribedUeAmbr": {
          "downlink": "2 Gbps",
          "uplink": "1 Gbps"
        },
      },
      "SessionManagementSubscriptionData": {
        "singleNssai": {
          "sst": 1,
          "sd": "010203"
        },
        "dnnConfigurations": {
          "internet": {
            "sscModes": {
              "defaultSscMode": "SSC_MODE_1",
              "allowedSscModes": ["SSC_MODE_1", "SSC_MODE_2", "SSC_MODE_3"]
            },
            "pduSessionTypes": {
              "defaultSessionType": "IPV4",
              "allowedSessionTypes": ["IPV4"]
            },
            "sessionAmbr": {
              "uplink": "2 Gbps",
              "downlink": "1 Gbps"
            },
            "5gQosProfile": {
              "5qi": 9,
              "arp": {
                "priorityLevel": 8
              },
              "priorityLevel": 8
            }
          }
        }
      },
      "SmfSelectionSubscriptionData": {
        "subscribedSnssaiInfos": {
          "01010203": {
            "dnnInfos": [
              {
                "dnn": "internet"
              }
            ]
          },
          "01112233": {
            "dnnInfos": [
              {
                "dnn": "internet"
              }
            ]
          }
        },
      },
      "AmPolicyData": {
        "subscCats": [
          "free5gc"
        ]
      },
      "SmPolicyData": {
        "smPolicySnssaiData": {
          "01010203": {
            "snssai": {
              "sst": 1,
              "sd": "010203"
            },
            "smPolicyDnnData": {
              "internet": {
                "dnn": "internet"
              }
            }
          },
          "01112233": {
            "snssai": {
              "sst": 1,
              "sd": "112233"
            },
            "smPolicyDnnData": {
              "internet": {
                "dnn": "internet"
              }
            }
          }
        }
      }
    };

    this.props.onSubmit(subscriberData);
  }

  render() {
    return (
      <Modal
        show={this.props.open}
        className={"fields__edit-modal theme-light"}
        backdrop={"static"}
        onHide={this.props.setOpen.bind(this, false)}>
        <Modal.Header closeButton>
          <Modal.Title id="example-modal-sizes-title-lg">
            {this.state.editMode ? "Edit Subscriber" : "New Subscriber"}
          </Modal.Title>
        </Modal.Header>

        <Modal.Body>
          {this.state.rerenderCounter % 2 === 0 &&
            <Form schema={this.schema}
              uiSchema={this.uiSchema}
              formData={this.state.formData}
              onChange={this.onChange.bind(this)}
              onSubmit={this.onSubmitClick.bind(this)} />
          }
        </Modal.Body>
      </Modal>
    );

  }


 
}

export default SubscriberModal;
