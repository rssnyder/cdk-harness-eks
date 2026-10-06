import * as cdk from 'aws-cdk-lib/core';
import { Template } from 'aws-cdk-lib/assertions';
import { CdkEksStack, CdkEksStackProps } from '../lib/cdk-eks-stack';

const manifests = (extra: Partial<CdkEksStackProps> = {}) => {
  const stack = new CdkEksStack(new cdk.App(), 'T', {
    env: { account: '123456789012', region: 'us-east-1' },
    harnessAccountId: 'a',
    harnessManagerEndpoint: 'https://m',
    harnessDelegateToken: 't',
    harnessDelegateImage: 'img:1',
    harnessOidcProviderHost: 'accounts.harness.io',
    vpcId: 'vpc-1',
    environment: 'dev',
    clusterName: 'buildfarm',
    tags: { team: 'platform' },
    allowedImageRegistries: ['123456789012.dkr.ecr.us-east-1.amazonaws.com/'],
    ...extra,
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

test('personas, break-glass alarm, ECR, DLM and Velero', () => {
  const role = (n: string) => `arn:aws:iam::123456789012:role/${n}`;
  const { t } = manifests({
    environment: 'prod',
    enableVelero: true,
    enableGuardDutyAgent: true,
    ecrRepositoryNames: ['app'],
    accessEntries: [
      { persona: 'engineer', roleArn: role('eng') },
      { persona: 'support', roleArn: role('sup') },
      { persona: 'breakglass', roleArn: role('bg') },
    ],
  });
  // engineer has no prod access
  t.resourceCountIs('AWS::EKS::AccessEntry', 2);
  t.hasResourceProperties('AWS::EKS::AccessEntry', {
    PrincipalArn: role('sup'),
    AccessPolicies: [{ AccessScope: { Type: 'namespace' } }],
  });
  t.hasResourceProperties('AWS::Logs::MetricFilter', {
    FilterPattern: '{ $.user.username = "*assumed-role/bg/*" }',
  });
  t.hasResourceProperties('AWS::ECR::Repository', { ImageTagMutability: 'IMMUTABLE', ImageScanningConfiguration: { ScanOnPush: true } });
  t.resourceCountIs('AWS::DLM::LifecyclePolicy', 1);
  t.hasResourceProperties('AWS::S3::Bucket', { VersioningConfiguration: { Status: 'Enabled' } });
  t.hasResourceProperties('AWS::EKS::Addon', { AddonName: 'aws-guardduty-agent' });
  t.hasResourceProperties('AWS::EKS::Addon', { AddonName: 'amazon-cloudwatch-observability' });
});

test('resource names follow the {environment}-{clustername} standard', () => {
  const { t } = manifests();
  t.hasResourceProperties('Custom::AWSCDK-EKS-Cluster', { Config: { name: 'dev-buildfarm' } });
  t.hasResourceProperties('AWS::IAM::Role', { RoleName: 'dev-buildfarm-cluster-role' });
  t.hasResourceProperties('AWS::IAM::Role', { RoleName: 'dev-buildfarm-node-role' });
  t.hasResourceProperties('AWS::EKS::Nodegroup', { NodegroupName: 'dev-buildfarm-ng-build' });
  t.hasResourceProperties('AWS::EC2::LaunchTemplate', { LaunchTemplateName: 'dev-buildfarm-lt-build' });
});

test('delegate token can be synced from Secrets Manager via External Secrets', () => {
  const { json } = manifests({ harnessDelegateToken: undefined, harnessDelegateTokenSecretName: 'harness/delegate-token' });
  for (const s of ['ExternalSecret', 'external-secrets', 'existingDelegateToken', 'harness/delegate-token']) {
    expect(json).toContain(s);
  }
  expect(json).not.toContain('"delegateToken"');
});
