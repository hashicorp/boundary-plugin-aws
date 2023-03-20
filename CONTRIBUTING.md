# Contributing

Create a new package when adding support to a new service in the aws plugin. The package name should be named after the service name found [here](https://github.com/hashicorp/boundary/tree/main/internal/proto/plugin/v1).

## Service Packages

- A service package should contain an `attributes.go` file, which contains all attributes associated to the service in addition to `CredentialAttributes`, which is defined in `internal/credential/attributes.go`.
- A service package should contain an `state.go` file, which contains the logic and definition of the service's persisted state.
- A service package should contain an `plugin.go` file, which contains the implemented method defined the the services proto definition found [here](https://github.com/hashicorp/boundary/tree/main/internal/proto/plugin/v1).

## Credential Package

This package contains all logic used for authorizing aws sessions. Any changes applied to this package will affect how all services handle aws sessions.

## Plugin.go

Found in `plugin/plugin.go`. This file contains the AwsPlugin struct definition, which contains the struct composition of all services that the plugin supports. Add your newly defined plugin service struct as a struct composition to the AwsPlugins struct.

## Testing

Please add end to end tests here in `testing/e2e_{service}_test.go`. Any aws terraform files should be stored in `testing/testdata/{service}/*.tf`