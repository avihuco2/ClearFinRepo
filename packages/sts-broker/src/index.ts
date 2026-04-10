// @clearfin/sts-broker — JIT AWS STS credential issuance scoped to tenants
export { STSBroker } from "./sts-broker.js";
export type {
  STSError,
  STSClient,
  AssumeRoleInput,
  AssumeRoleOutput,
  ServiceRegistry,
  TenantStore,
  STSBrokerConfig,
} from "./sts-broker.js";
