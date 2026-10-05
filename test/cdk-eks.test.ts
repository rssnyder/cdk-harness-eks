import * as cdk from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import { CdkEksStack } from '../lib/cdk-eks-stack';

const manifests = () => {
  const stack = new CdkEksStack(new cdk.App(), 'T', {
    env: { account: '123456789012', region: 'us-east-1' },
    harnessAccountId: 'a',
    harnessManagerEndpoint: 'https://m',
    harnessDelegateToken: 't',
    harnessDelegateImage: 'img:1',
    harnessOidcProviderHost: 'accounts.harness.io',
    vpcId: 'vpc-1',
    tags: { team: 'platform' },
    allowedImageRegistries: ['123456789012.dkr.ecr.us-east-1.amazonaws.com/'],
  });
  const t = Template.fromStack(stack);
  return { t, json: JSON.stringify(t.toJSON()) };
};

test('namespace guardrails, network policy and registry policy are created', () => {
  const { t, json } = manifests();
  t.hasResourceProperties('AWS::EKS::Addon', {
    AddonName: 'vpc-cni',
    ConfigurationValues: '{"enableNetworkPolicy":"true"}',
  });
  for (const kind of ['ResourceQuota', 'LimitRange', 'default-deny', 'allow-dns', 'ValidatingAdmissionPolicy']) {
    expect(json).toContain(kind);
  }
  expect(json).toContain('"team"');
});
