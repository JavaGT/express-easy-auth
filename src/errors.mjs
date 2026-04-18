export const ERROR = {
  not_authenticated: {
    code: 401,
    message: 'No valid session or API key provided',
  },
  insufficient_scope: {
    code: 403,
    message: 'Authenticated but missing required scope.* permission',
  },
  api_key_revoked: {
    code: 403,
    message: 'API key has been revoked',
  },
  api_key_project_mismatch: {
    code: 403,
    message: "API key's project_id does not match route parameter",
  },
  not_project_member: {
    code: 403,
    message: 'Session user is not a member of the project',
  },
  owner_required_for_api_key: {
    code: 403,
    message: 'Only project owners may manage API keys',
  },
  owner_required_for_api_key_secret: {
    code: 403,
    message: 'Only owners may view plaintext API key secrets',
  },
  project_not_active: {
    code: 403,
    message: 'Project is not active',
  },
  project_soft_deleted: {
    code: 404,
    message: 'Project is soft-deleted; API access restricted',
  },
  entity_in_recycle_bin: {
    code: 404,
    message: 'Requested entity was soft-deleted (check recycling bin)',
  },
  recycle_retention_expired: {
    code: 410,
    message: 'Entity was purged after 24h retention window',
  },
  purge_confirmation_required: {
    code: 400,
    message: 'Permanent purge requires explicit owner confirmation',
  },
  owner_required_for_purge: {
    code: 403,
    message: 'Only project owners may purge from recycling bin',
  },
  session_step_up_required: {
    code: 401,
    message: 'Sensitive action requires recent re-authentication (<5 min)',
  },
  validation_error: {
    code: 400,
    message: 'Request body/query failed schema validation',
  },
  not_found: {
    code: 404,
    message: 'Resource does not exist (and not in recycle bin)',
  },
  conflict: {
    code: 409,
    message: 'Request conflicts with current resource state',
  },
};