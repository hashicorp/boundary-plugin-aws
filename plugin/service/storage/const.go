package storage

const (
	// ConstAwsEndpointUrl is the key for the endpoint url in the aws s3 client.
	ConstAwsEndpointUrl = "endpoint_url"

	// defaultStreamChunkSize is the recommened chunk size for sending data through a stream
	defaultStreamChunkSize = 65536 // 64 KiB
)
