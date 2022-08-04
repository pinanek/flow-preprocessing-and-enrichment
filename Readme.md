# flow-preprocessing-and-enrichment

A small Go program that processes flow data and enriches flow-based IDS predictions with additional information 😎.

## How it works

This program will do a couple of things:

1. Request data from ElasticSearch which stores data from FileBeat using [NetFlow modules](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-netflow.html).

2. Create a list of selected features (each element is a `Netflow` object, see below) and send them to the [flow-based IDS](https://github.com/thihuynhdotexe/flow-based-IDS) (created by my teammate 😁). The program will receive a list of predictions according to each `Netflow` object.

```go
type Netflow struct {
	SourceIpv4Address           string `json:"source_ipv4_address"`
	DestinationIpv4Address      string `json:"destination_ipv4_address"`
	SourceIpv4PrefixLength      int    `json:"source_ipv4_prefix_length"`
	DestinationIpv4PrefixLength int    `json:"destination_ipv4_prefix_length"`
	SourceTransportPort         int    `json:"source_transport_port"`
	DestinationTransportPort    int    `json:"destination_transport_port"`
	ProtocolIdentifier          int    `json:"protocol_identifier"`
	PacketDeltaCount            int    `json:"packet_delta_count"`
	OctetDeltaCount             int    `json:"octet_delta_count"`
	TcpControlBits              int    `json:"tcp_control_bits"`
	FlowDurationMilliseconds    int    `json:"flow_duration_milliseconds"`
	PostPacketDeltaCount        int    `json:"post_packet_delta_count"`
	PostOctetDeltaCount         int    `json:"post_octet_delta_count"`
	IxiaL7AppId                 int    `json:"ixia_l7_app_id"`
}
```

3. Finally, the program logs the prediction and adds additional information (ip, port, timestamp, ...) with each record. Logs will store in `log/` folder.

```log
Flow IDS prediction: Timestamp=2022-07-19T12:05:25.000Z, Score=0.781500, Malicious=true, Source=10.0.0.1:39954, Destination=10.0.0.4:80, Protocol=6, ExporterIp=192.168.142.140:35567
Flow IDS prediction: Timestamp=2022-07-19T11:53:14.000Z, Score=0.000100, Malicious=false, Source=10.0.0.4:80, Destination=10.0.0.1:39924, Protocol=6, ExporterIp=192.168.142.140:35567
```

## Usage

- Create a file `.env` and add the following variables

```
ELASTIC_USERNAME={Your elastic username}
ELASTIC_PASSWORD={Your elastic password}
ELASTIC_REQUEST_URL={Your elastic request url, ex: https://192.168.142.141:9200/filebeat-*/_search}
PREDICT_REQUEST_URL={Your deployed flow-based IDS request url, ex: http://127.0.0.1:5000/predict}
```

- Run 🎉.
