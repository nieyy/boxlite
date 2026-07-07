# SshAccessValidationDto


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**valid** | **boolean** | Whether the SSH access token is valid | [default to undefined]
**boxId** | **string** | ID of the box this SSH access is for | [default to undefined]
**unixUser** | **string** | Unix user for real-SSH access; null for legacy exec-bridge tokens | [optional] [default to undefined]

## Example

```typescript
import { SshAccessValidationDto } from './api';

const instance: SshAccessValidationDto = {
    valid,
    boxId,
    unixUser,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
