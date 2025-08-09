# Client Configuration

## Endpoints

### `GET` /relivewp/config/version

Fetches the latest and minimum client configuration versions.

##### Returns

A ClientConfigVersions structure. Contains both a minimum and latest version, the client will only download the latest version if the minimum version is newer than the local copy. As a result, more often than not these numbers will be the same.

### `GET` /relivewp/config

Fetches the latest client configuration database.

##### Returns
An SQLite database containing the latest client configuration information.

## Structures

#### `ClientConfigVersions` Object

| Field | Type | Description |
| - | - | - |
| `min_version` | int32 | The minimum supported client configuration version |
| `latest_version` | int32 | The latest supported client configuration version |

##### Example

```json
{ "min_version": 12, "latest_version": 14 }
```
