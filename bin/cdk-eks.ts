#!/opt/homebrew/opt/node/bin/node
// Load inputs from a local, git-ignored .env file so they can be edited without
// touching code. `override: true` makes .env values win over any stale variables
// already exported in the shell (plain `dotenv/config` does NOT override those).
import * as dotenv from 'dotenv';
dotenv.config({ override: true });
import * as cdk from 'aws-cdk-lib/core';
import { CdkEksStack } from '../lib/cdk-eks-stack';

/** Read a required environment variable, failing fast if it is unset/empty. */
function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing required environment variable ${name}. ` +
        `Set it in your shell/CI secret store before running cdk (do not hard-code it).`,
    );
  }
  return value;
}

/** Parse a comma/whitespace-separated environment variable into a string list. */
function envList(name: string): string[] {
  return (process.env[name] ?? '')
    .split(/[\s,]+/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
}

/** Parse EKS_TAGS="key=value,key2=value2" into a record. */
function envTags(name: string): Record<string, string> {
  return Object.fromEntries(
    envList(name).map((kv) => {
      const i = kv.indexOf('=');
      if (i < 1) throw new Error(`${name}: expected key=value, got "${kv}"`);
      return [kv.slice(0, i), kv.slice(i + 1)];
    }),
  );
}

const app = new cdk.App();
new CdkEksStack(app, 'HarnessBuildFarm', {
  /* Vpc.fromLookup requires an explicit account/region, taken here from the
   * current CLI configuration (AWS_PROFILE / AWS_REGION / credentials). */
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },

  /* Harness delegate configuration, sourced from the environment so secrets are
   * never committed. The delegate token in particular must come from a secret
   * store (CI secret, AWS Secrets Manager, etc.). */
  harnessAccountId: requireEnv('HARNESS_ACCOUNT_ID'),
  harnessDelegateToken: requireEnv('HARNESS_DELEGATE_TOKEN'),
  harnessManagerEndpoint: process.env.HARNESS_MANAGER_ENDPOINT ?? 'https://app.harness.io/gratis',
  harnessDelegateImage:
    process.env.HARNESS_DELEGATE_IMAGE ??
    'us-docker.pkg.dev/gar-prod-setup/harness-public/harness/delegate:26.07.89706',
  harnessOidcProviderHost: process.env.HARNESS_OIDC_PROVIDER_HOST ?? 'accounts.harness.io',

  /* VPC configuration */
  vpcId: requireEnv('VPC_ID'),

  /* Optional cluster-access inputs (comma/space-separated lists). Security
   * groups allowed to reach the private API server, and IAM role ARNs granted
   * cluster access via EKS access entries. */
  apiServerIngressSecurityGroupIds: envList('EKS_API_INGRESS_SECURITY_GROUP_IDS'),
  clusterAdminRoleArns: envList('EKS_CLUSTER_ADMIN_ROLE_ARNS'),

  /* Email subscribed to the SNS topic that EKS audit-log alarms notify. */
  alarmNotificationEmail: process.env.EKS_ALARM_EMAIL,

  /* Generic tags applied to all AWS resources and namespace labels. */
  tags: envTags('EKS_TAGS'),

  /* For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html */
});
