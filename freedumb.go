package freedumb

import "time"

type InitializationPayload struct {
	InstanceId         string
	InstanceIamRoleArn string
	Region             string
	IdpUrl             string
	RoleArn            string
}

type AssumeRoleRequest struct {
	InstanceId         string
	InstanceIamRoleArn string
	RequestedRoleArn   string
}

type AssumeRoleResponse struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
}

const InitializationPayloadPort = 31990
const HttpProxyPort = 31991
const CredentialServerPort = 31992
