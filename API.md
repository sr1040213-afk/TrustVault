# HTTP route reference

State-changing forms require CSRF tokens.

|Method|Path|Access|Purpose|
|-|-|-|-|
|GET|`/`|Public|Landing|
|GET/POST|`/register`|Public|Create viewer account by default|
|GET/POST|`/login`|Public|Authenticate|
|POST|`/logout`|Authenticated|Logout|
|GET|`/dashboard`|Authenticated|Owned/shared docs|
|GET/POST|`/documents/upload`|Owner|Upload|
|GET|`/documents`|Authenticated|Search accessible docs|
|GET|`/documents/<id>`|Owner or active Read/Edit grant|View|
|GET|`/documents/<id>/download`|Owner or active Read/Edit grant|Verify SHA-256/download|
|POST|`/documents/<id>/share`|Owner|Grant Read/Edit|
|POST|`/documents/<id>/revoke/<user\_id>`|Owner|Revoke|
|POST|`/documents/<id>/edit`|Owner or active Edit grant|Update metadata|
|POST|`/documents/<id>/delete`|Owner|Soft-delete|
|GET|`/admin`|Admin|User/document/audit monitoring|
|POST|`/admin/users/<id>/toggle`|Admin|Activate/deactivate|
| POST | /admin/users/<id>/role | Admin | Set Owner/Viewer/Admin |
| GET | /activity | Authenticated | View own activity history |
| POST | /admin/documents/<id>/delete | Admin | Soft-delete document |

Unauthorized detail/download returns 404; unauthorized mutation returns 403; integrity mismatch returns 409. Admin does not automatically gain document access.
