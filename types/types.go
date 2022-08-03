package types

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

type NetflowExporter struct {
	Address   string `json:"address"`
	Timestamp string `json:"timestamp"`
}

type NetflowWithExporter struct {
	Netflow
	Exporter NetflowExporter `json:"exporter"`
}

type Document struct {
	TimeOut bool `json:"time_out"`

	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`

		Hits []struct {
			Source struct {
				Netflow   Netflow `json:"netflow"`
				Timestamp string  `json:"@timestamp"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

type DocumentWithExporter struct {
	TimeOut bool `json:"time_out"`

	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`

		Hits []struct {
			Source struct {
				Netflow   NetflowWithExporter `json:"netflow"`
				Timestamp string              `json:"@timestamp"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}
