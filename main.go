package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"preprocessing/types"
	"strings"

	"github.com/joho/godotenv"
)

const SAVED_TIMESTAMP_FILE_NAME = "saved-timestamp.txt"

const LOG_DIRECTORY = "log/"

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

func readSavedTimestamp() string {
	data, err := os.ReadFile(SAVED_TIMESTAMP_FILE_NAME)
	if err != nil {
		return "1970-01-01T00:00:00.000Z"
	}

	return string(data)
}

func saveNewTimestamp(newTimestamp string) {
	err := os.WriteFile(SAVED_TIMESTAMP_FILE_NAME, []byte(newTimestamp), 0755)
	checkError(err)
}

func createInsecureClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	return client
}

func getNetflowData(elasticRequestUrl string, elasticUsername string, elasticPassword string) ([]types.Netflow, []types.NetflowExporter) {
	body := fmt.Sprintf(`{"size":10000,"query":{"bool":{"must":[{"match":{"input.type":"netflow"}},{"exists":{"field":"netflow.source_ipv4_address"}},{"exists":{"field":"netflow.destination_ipv4_address"}},{"exists":{"field":"netflow.protocol_identifier"}}],"filter":[{"range":{"@timestamp":{"gt":"%s","lte":"now"}}}]}},"_source":["netflow.source_ipv4_address","netflow.destination_ipv4_address","netflow.source_ipv4_prefix_length","netflow.destination_ipv4_prefix_length","netflow.source_transport_port","netflow.destination_transport_port","netflow.protocol_identifier","netflow.packet_delta_count","netflow.octet_delta_count","netflow.tcp_control_bits","netflow.flow_duration_milliseconds","netflow.post_packet_delta_count","netflow.post_octet_delta_count","netflow.ixia_l7_app_id","netflow.exporter.address","netflow.exporter.timestamp","@timestamp"],"sort":[{"@timestamp":{"order":"asc"}}]}`,
		readSavedTimestamp())

	request, _ := http.NewRequest("GET", elasticRequestUrl, strings.NewReader(body))

	request.Header.Add("Content-Type", "application/json; charset=UTF-8")
	request.SetBasicAuth(elasticUsername, elasticPassword)

	client := createInsecureClient()

	response, err := client.Do(request)
	checkError(err)

	defer response.Body.Close()

	var document types.DocumentWithExporter
	json.NewDecoder(response.Body).Decode(&document)

	var netflowData []types.Netflow
	var exporters []types.NetflowExporter

	if document.TimeOut || document.Hits.Total.Value == 0 {
		return netflowData, exporters
	}

	saveNewTimestamp(document.Hits.Hits[len(document.Hits.Hits)-1].Source.Timestamp)

	for _, data := range document.Hits.Hits {
		netflowData = append(netflowData, data.Source.Netflow.Netflow)
		exporters = append(exporters, data.Source.Netflow.Exporter)
	}

	return netflowData, exporters
}

func getPredictedValues(netflowData []types.Netflow, predictRequestUrl string) []float32 {
	body, _ := json.Marshal(netflowData)

	if len(body) == 4 {
		return nil
	}

	request, _ := http.NewRequest("POST", predictRequestUrl, bytes.NewReader(body))
	request.Header.Add("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	response, err := client.Do(request)
	checkError(err)

	defer response.Body.Close()

	var predictedValues []float32
	json.NewDecoder(response.Body).Decode(&predictedValues)

	return predictedValues
}

func logNetflowPredict(netflowData []types.Netflow, exporters []types.NetflowExporter, predictedValues []float32) {
	if len(netflowData) == 0 {
		return
	}

	fileName := filepath.Join(LOG_DIRECTORY, "netflow-detected.log")

	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	checkError(err)

	var logData []string
	for i := 0; i < len(netflowData); i++ {
		data := netflowData[i]
		exporter := exporters[i]

		logData = append(logData, fmt.Sprintf("Flow IDS prediction: Timestamp=%s, Score=%f, Malicious=%t, Source=%s:%d, Destination=%s:%d, Protocol=%d, ExporterIp=%s",
			exporter.Timestamp,
			predictedValues[i],
			predictedValues[i] > 0.5,
			data.SourceIpv4Address,
			data.SourceTransportPort,
			data.DestinationIpv4Address,
			data.DestinationTransportPort,
			data.ProtocolIdentifier,
			exporter.Address))
	}

	file.WriteString(strings.Join(logData[:], "\n") + "\n")

	defer file.Close()
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	elasticRequestUrl := os.Getenv("ELASTIC_REQUEST_URL")
	predictRequestUrl := os.Getenv("PREDICT_REQUEST_URL")
	elasticUsername := os.Getenv("ELASTIC_USERNAME")
	elasticPassword := os.Getenv("ELASTIC_PASSWORD")

	netflowData, exporters := getNetflowData(elasticRequestUrl, elasticUsername, elasticPassword)
	predictedValues := getPredictedValues(netflowData, predictRequestUrl)
	logNetflowPredict(netflowData, exporters, predictedValues)
}
