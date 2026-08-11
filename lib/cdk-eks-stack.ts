import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import { KubectlV36Layer } from '@aws-cdk/lambda-layer-kubectl-v36';

export interface CdkEksStackProps extends cdk.StackProps {
  /** Harness account identifier that the delegate registers against. */
  readonly harnessAccountId: string;
  /** Harness manager endpoint URL (e.g. https://app.harness.io/gratis). */
  readonly harnessManagerEndpoint: string;
  /**
   * Harness delegate token. This is a secret and must never be hard-coded or
   * committed; it is sourced from the environment in bin/cdk-eks.ts.
   */
  readonly harnessDelegateToken: string;
}

export class CdkEksStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: CdkEksStackProps) {
    super(scope, id, props);

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', {
      vpcId: 'vpc-02767cb7b8b634d54',
    });

    // DP-7: customer-managed key for KMS envelope encryption of Kubernetes secrets.
    const secretsKey = new kms.Key(this, 'EksSecretsKey', {
      enableKeyRotation: true,
      description: `KMS CMK for EKS Kubernetes secret envelope encryption (${id})`,
    });

    const cluster = new eks.Cluster(this, 'Cluster', {
      version: eks.KubernetesVersion.V1_36,
      defaultCapacity: 5,
      defaultCapacityInstance: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.XLARGE),
      kubectlLayer: new KubectlV36Layer(this, 'kubectl'),
      vpc,
      vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_ISOLATED }], // this is because I host my own NAT, more than likley you want PRIVATE_WITH_EGRESS or PRIVATE_WITH_NAT

      // DP-7: encrypt Kubernetes secrets at rest with the customer-managed key.
      secretsEncryptionKey: secretsKey,

      // INFRA-1: private-only API server endpoint. kubectl/CDK must reach it from
      // within the VPC; CDK runs its kubectl provider inside the cluster VPC.
      endpointAccess: eks.EndpointAccess.PRIVATE,

      // LOG-1: enable all five control plane log types (audit + authenticator are
      // the minimum required; all five are recommended).
      clusterLogging: [
        eks.ClusterLoggingTypes.API,
        eks.ClusterLoggingTypes.AUDIT,
        eks.ClusterLoggingTypes.AUTHENTICATOR,
        eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
        eks.ClusterLoggingTypes.SCHEDULER,
      ],

      // IAM-1: authenticate via AWS IAM principals through EKS access entries.
      authenticationMode: eks.AuthenticationMode.API,
    });

    new eks.HelmChart(this, 'HarnessDelegate', {
      cluster: cluster,
      chart: 'harness-delegate-ng',
      repository: 'https://app.harness.io/storage/harness-download/delegate-helm-chart/',
      namespace: 'harness-delegate-ng',
      createNamespace: true,
      // Helm release names must be lowercase RFC 1123 DNS-1123 labels, so the
      // mixed-case stack name ('HarnessBuildFarm') can't be used directly.
      release: this.stackName.toLowerCase(),
      values: {
        delegateName: 'helm-delegate',
        tags: `aws,eks,build-farm,${this.stackName}`,
        accountId: props.harnessAccountId,
        delegateToken: props.harnessDelegateToken,
        managerEndpoint: props.harnessManagerEndpoint,
        delegateDockerImage: 'us-docker.pkg.dev/gar-prod-setup/harness-public/harness/delegate:26.07.89706',
        replicas: 1,
        upgrader: {
          enabled: true,
        },
      },
    });

  }
}
