import React, { Component } from 'react';
import { Modal } from "react-bootstrap";
import Form from "react-jsonschema-form";
import PropTypes from 'prop-types';
import _ from 'lodash';

let snssaiToString = (snssai) => snssai.sst.toString(16).padStart(2, '0').toUpperCase() + snssai.sd

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
        pattern: "^[0-9]{5,6}$",
        default: "20893",
      },
      ueId: {
        type: "string",
        title: "SUPI (IMSI)",
        pattern: "^[0-9]{10,15}$",
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
        pattern: "^[A-Fa-f0-9]{32}$",
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
        pattern: "^[A-Fa-f0-9]{32}$",
        default: "8e27b6af0e692e750f32667a3b14605d",
      },
      singleNssais: {
        type: "array",
        title: "Single NSSAI",
        items: { $ref: "#/definitions/snssai" },
        default: [
          {
            "sst": 1,
            "sd": "010203",
            "isDefault": true,
          },
          {
            "sst": 1,
            "sd": "112233",
            "isDefault": true,
          },
        ],
      },
    },
    definitions: {
      snssai: {
        type: "object",
        required: ["sst", "sd"],
        properties: {
          sst: {
            type: "integer",
            title: "SST",
            minimum: 0,
            maximum: 255,
          },
          sd: {
            type: "string",
            title: "SD",
            pattern: "^[A-Fa-f0-9]{6}$",
          },
          isDefault: {
            type: "boolean",
            title: "Default S-NSSAI",
            default: false,
          },
        },
      },
    },
  };

  uiSchema = {
    OPOPcSelect: {
      "ui:widget": "select",
    },
    authenticationMethod: {
      "ui:widget": "select",
    },
    singleNssais: {
      "ui:options": {
        "orderable": false
      },
      "isDefault": {
        "ui:widget": "radio",
      }
    }
  };

  componentDidUpdate(prevProps, prevState, snapshot) {
    if (prevProps !== this.props) {
      this.setState({ editMode: !!this.props.subscriber });

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
    const singleNssais = formData["singleNssais"];
    let subscribedSnssaiInfos = {};
    singleNssais.forEach(snssai => { // Should we merge default and non-default nssais?
      let key = snssai.sst.toString(16).padStart(2, '0');
      key += snssai.sd;
      subscribedSnssaiInfos[key] = {
        "dnnInfos": [
          {
            "dnn": "internet"
          }
        ]
      }
    });
    let smPolicySnssaiData = {};
    singleNssais.forEach(snssai => { // Should we merge default and non-default nssais?
      let key = snssai.sst.toString(16).padStart(2, '0');
      key += snssai.sd;
      smPolicySnssaiData[key] = {
        "snssai": snssai,
        "smPolicyDnnData": {
          "internet": {
            "dnn": "internet"
          }
        }
      }
    });

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
          "defaultSingleNssais": _.filter(formData["singleNssais"], snssai => !!snssai.isDefault),
          "singleNssais": _.filter(formData["singleNssais"], snssai => !snssai.isDefault),
        },
        "subscribedUeAmbr": {
          "downlink": "2 Gbps",
          "uplink": "1 Gbps",
        },
      },
      "SessionManagementSubscriptionData": _.map(formData["singleNssais"], snssai => {

        return {
          "singleNssai": {
            "sst": snssai.sst,
            "sd": snssai.sd
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
        }
      }),
      "SmfSelectionSubscriptionData": {
        "DnnInfosubscribedSnssaiInfos": _.fromPairs(
          _.map(formData["singleNssais"], snssai => [snssaiToString(snssai),
          {
            "dnnInfos": [
              {
                "dnn": "internet",
              },
            ]
          }]))
      },
      "AmPolicyData": {
        "subscCats": [
          "free5gc",
        ]
      },
      "SmPolicyData": {
        "smPolicySnssaiData": _.fromPairs(
          _.map(formData["singleNssais"], snssai => [snssaiToString(snssai),
          {
            "snssai": {
              "sst": snssai.sst,
              "sd": snssai.sd
            },
            "smPolicyDnnData": {
              "internet": {
                "dnn": "internet"
              },
            },
          }]))
      },
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
