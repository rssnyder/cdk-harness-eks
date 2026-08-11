#!/opt/homebrew/opt/node/bin/node
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

  /* For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html */
});
