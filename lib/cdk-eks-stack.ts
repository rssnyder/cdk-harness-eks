import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as dlm from 'aws-cdk-lib/aws-dlm';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
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
  readonly harnessDelegateToken?: string;
  /**
   * Name of an existing Secrets Manager secret (plain-string token, created out
   * of band) synced into the delegate namespace by External Secrets Operator.
   * Preferred over harnessDelegateToken, which lands in the synthesized template.
   */
  readonly harnessDelegateTokenSecretName?: string;
  /**
   * Container image for the Harness delegate (repository:tag). Pinned rather
   * than left to the chart default/upgrader so `helm upgrade` runs stay
   * idempotent (see the `upgrader.enabled: false` note below).
   */
  readonly harnessDelegateImage: string;
  /** VPC ID to use for the EKS cluster. */
  readonly vpcId: string;
  /**
   * Security group IDs permitted to reach the private EKS API server on 443
   * (e.g. a bastion or self-hosted NAT). Optional; empty means none are added.
   */
  readonly apiServerIngressSecurityGroupIds?: string[];
  /**
   * IAM role ARNs granted cluster access via EKS access entries (cluster-admin
   * scope). Optional; empty means no access entries are created.
   */
  readonly clusterAdminRoleArns?: string[];
  /**
   * Email address subscribed to the SNS topic that EKS audit-log alarms notify.
   * Optional; empty means the topic is created but no email subscription added.
   */
  readonly alarmNotificationEmail?: string;
  /**
   * Host of the Harness OIDC issuer, used to build
   * https://<host>/ng/api/oidc/account/<harnessAccountId> for the IAM OIDC
   * provider. Defaults to 'accounts.harness.io' in bin/cdk-eks.ts.
   */
  readonly harnessOidcProviderHost: string;
  /**
   * Cluster autoscaler image repository and tag. Defaults to the Docker Hub mirror;
   * swap to a public ECR repo (e.g. public.ecr.aws/autoscaling/cluster-autoscaler)
   * if Docker Hub's anonymous pull rate limit becomes an issue.
   */
  readonly clusterAutoscalerImageRepository?: string;
  readonly clusterAutoscalerImageTag?: string;
  /**
   * Arbitrary tag key/values applied to every taggable AWS resource in the
   * stack and, as labels, to the Kubernetes namespaces. Values used as labels
   * must be valid k8s label values (<=63 chars, alphanumeric, '-', '_', '.').
   */
  readonly tags?: Record<string, string>;
  /**
   * Image registry prefixes (with trailing '/') pods may pull from in
   * application namespaces, e.g. `<acct>.dkr.ecr.<region>.amazonaws.com/`.
   * Empty/unset means no registry policy is created.
   */
  readonly allowedImageRegistries?: string[];
  /** CIDRs allowed to reach the API server over the public endpoint. Unset keeps it private-only. */
  readonly publicEndpointCidrs?: string[];
  /** Short cluster name; resources are named `{environment}-{clusterName}-...`. */
  readonly clusterName: string;
  /** Deployment environment; drives naming and persona access (engineer: dev=admin, test=view, prod=none). */
  readonly environment: 'dev' | 'test' | 'prod';
  /** Persona -> IAM role (e.g. Okta-federated) granted EKS access entries scoped to the app namespaces. */
  readonly accessEntries?: Array<{ persona: 'engineer' | 'devops' | 'support' | 'breakglass'; roleArn: string }>;
  /** Install the GuardDuty runtime agent add-on. Leave off if org-level GuardDuty auto-manages it. */
  readonly enableGuardDutyAgent?: boolean;
  /** ECR repositories to create (KMS-encrypted, scan-on-push, immutable tags). */
  readonly ecrRepositoryNames?: string[];
  /** Deploy Velero (cluster-state backups to an encrypted, versioned S3 bucket). */
  readonly enableVelero?: boolean;
  /** Velero AWS plugin image. */
  readonly veleroPluginImage?: string;
  /** Snapshots retained by the daily EBS DLM policy (default 7). */
  readonly ebsSnapshotRetentionCount?: number;
  /** Deny (true) vs. only warn/audit (false, default) on disallowed registries. */
  readonly enforceAllowedImageRegistries?: boolean;
}

export class CdkEksStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: CdkEksStackProps) {
    super(scope, id, props);

    if (!props.harnessDelegateToken && !props.harnessDelegateTokenSecretName) {
      throw new Error('Set harnessDelegateTokenSecretName (preferred) or harnessDelegateToken.');
    }

    // Naming standard: {environment}-{clustername}[-suffix].
    const prefix = `${props.environment}-${props.clusterName}`;
    const tags = props.tags ?? {};
    for (const [k, v] of Object.entries(tags)) {
      cdk.Tags.of(this).add(k, v);
    }

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', {
      vpcId: props.vpcId,
    });

    // DP-7: customer-managed key for KMS envelope encryption of Kubernetes secrets.
    const secretsKey = new kms.Key(this, 'EksSecretsKey', {
      enableKeyRotation: true,
      description: `KMS CMK for EKS Kubernetes secret envelope encryption (${id})`,
    });

    const clusterSubnets = { subnetType: ec2.SubnetType.PRIVATE_ISOLATED } // this is because I host my own NAT, more than likley you want PRIVATE_WITH_EGRESS or PRIVATE_WITH_NAT

    const clusterRole = new iam.Role(this, 'ClusterRole', {
      roleName: `${prefix}-cluster-role`,
      assumedBy: new iam.ServicePrincipal('eks.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEKSClusterPolicy')],
    });
    const nodeRole = new iam.Role(this, 'NodeRole', {
      roleName: `${prefix}-node-role`,
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEKSWorkerNodePolicy'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEKS_CNI_Policy'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEC2ContainerRegistryReadOnly'),
      ],
    });

    const cluster = new eks.Cluster(this, 'Cluster', {
      clusterName: prefix,
      role: clusterRole,
      version: eks.KubernetesVersion.V1_36,
      // No default capacity — worker nodes come from the hardened Bottlerocket
      // managed node group defined below.
      defaultCapacity: 0,
      // The cluster is a custom resource, so stack-level Tags do not reach it.
      tags: props.tags,
      kubectlLayer: new KubectlV36Layer(this, 'kubectl'),
      vpc,
      vpcSubnets: [clusterSubnets], 

      // DP-7: encrypt Kubernetes secrets at rest with the customer-managed key.
      secretsEncryptionKey: secretsKey,

      // INFRA-1: private-only API server endpoint. kubectl/CDK must reach it from
      // within the VPC; CDK runs its kubectl provider inside the cluster VPC.
      // Optionally also expose the endpoint to approved CIDRs (e.g. a test workstation).
      endpointAccess: props.publicEndpointCidrs?.length
        ? eks.EndpointAccess.PUBLIC_AND_PRIVATE.onlyFrom(...props.publicEndpointCidrs)
        : eks.EndpointAccess.PRIVATE,

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

    // Federates the per-account Harness OIDC issuer into IAM so Harness
    // pipelines can AssumeRoleWithWebIdentity into AWS without static
    // credentials.
    const harnessOidcProvider = new iam.OpenIdConnectProvider(this, 'HarnessOidcProvider', {
      url: `https://${props.harnessOidcProviderHost}/ng/api/oidc/account/${props.harnessAccountId}`,
      clientIds: ['sts.amazonaws.com'],
    });

    // Role Harness pipelines assume via the OIDC provider above (no static
    // credentials). Trust is scoped to the aud claim only, for now — anyone
    // holding a valid token from this Harness account's issuer can assume it.
    // Permissions below are intentionally broad (Resource: '*') as a starting
    // point; tighten to specific secret/repo/bucket ARNs once those are known.
    // openIdConnectProviderIssuer is a deploy-time token (derived from the
    // provider's ARN), so it can't be used directly as a JS object key —
    // CfnJson defers building this map until deploy time instead.
    const harnessOidcAudCondition = new cdk.CfnJson(this, 'HarnessOidcAudCondition', {
      value: {
        [`${harnessOidcProvider.openIdConnectProviderIssuer}:aud`]: 'sts.amazonaws.com',
      },
    });

    const harnessOidcWorkloadRole = new iam.Role(this, 'HarnessOidcWorkloadRole', {
      assumedBy: new iam.OpenIdConnectPrincipal(harnessOidcProvider, {
        StringEquals: harnessOidcAudCondition,
      }),
      description: 'Federated (Harness OIDC) role: Secrets Manager read, ECR build/push, S3 object write.',
    });

    harnessOidcWorkloadRole.addToPolicy(new iam.PolicyStatement({
      sid: 'SecretsManagerReadAny',
      actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret', 'secretsmanager:ListSecrets'],
      resources: ['*'],
    }));

    harnessOidcWorkloadRole.addToPolicy(new iam.PolicyStatement({
      // GetAuthorizationToken (needed by `docker login`) only supports
      // Resource: '*' — AWS rejects any other resource ARN on this action.
      sid: 'EcrAuth',
      actions: ['ecr:GetAuthorizationToken'],
      resources: ['*'],
    }));

    harnessOidcWorkloadRole.addToPolicy(new iam.PolicyStatement({
      sid: 'EcrBuildAndPush',
      actions: [
        'ecr:BatchCheckLayerAvailability',
        'ecr:GetDownloadUrlForLayer',
        'ecr:BatchGetImage',
        'ecr:PutImage',
        'ecr:InitiateLayerUpload',
        'ecr:UploadLayerPart',
        'ecr:CompleteLayerUpload',
        'ecr:CreateRepository',
        'ecr:DescribeRepositories',
        'ecr:ListImages',
        'ecr:DescribeImages',
      ],
      resources: ['*'],
    }));

    harnessOidcWorkloadRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowS3BucketAccess',
      actions: ['s3:PutObject', 's3:GetObject', 's3:ListBucket', 's3:DeleteObject'],
      resources: ['*'],
    }));

    harnessOidcWorkloadRole.addToPolicy(new iam.PolicyStatement({
      sid: 'AllowDescribeRegions',
      actions: ['ec2:DescribeRegions'],
      resources: ['*'],
    }));

    // DP-8: dedicated customer-managed key for worker node and persistent
    // volume encryption (kept separate from the secrets CMK for blast-radius).
    const nodeStorageKey = new kms.Key(this, 'NodeStorageKey', {
      enableKeyRotation: true,
      description: `KMS CMK for EKS node & EBS volume encryption (${id})`,
    });

    // Managed node groups launch instances via the Auto Scaling service-linked
    // role, which must be granted use of the CMK in the KEY POLICY (identity
    // policies alone are not enough) or instance launch fails.
    const asgServiceLinkedRole = new iam.ArnPrincipal(
      `arn:aws:iam::${this.account}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling`,
    );
    nodeStorageKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowAutoScalingSLRUseOfCMK',
      principals: [asgServiceLinkedRole],
      actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:DescribeKey'],
      resources: ['*'],
    }));
    nodeStorageKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowAutoScalingSLRCreateGrant',
      principals: [asgServiceLinkedRole],
      actions: ['kms:CreateGrant'],
      resources: ['*'],
      conditions: { Bool: { 'kms:GrantIsForAWSResource': 'true' } },
    }));

    // IAM-8 + DP-8: launch template enforcing IMDSv2 with a hop limit of 1 (so
    // non host-network pods cannot reach IMDS and assume the node role) and
    // encrypting both Bottlerocket volumes with the CMK.
    const nodeLaunchTemplate = new ec2.LaunchTemplate(this, 'NodeLaunchTemplate', {
      launchTemplateName: `${prefix}-lt-build`,
      requireImdsv2: true,
      httpPutResponseHopLimit: 1,
      blockDevices: [
        // Bottlerocket OS volume.
        { deviceName: '/dev/xvda', volume: ec2.BlockDeviceVolume.ebs(4, { encrypted: true, kmsKey: nodeStorageKey }) },
        // Bottlerocket data volume (container images & ephemeral storage).
        { deviceName: '/dev/xvdb', volume: ec2.BlockDeviceVolume.ebs(50, { encrypted: true, kmsKey: nodeStorageKey }) },
      ],
    });

    // INFRA-4 + RES-1: hardened Bottlerocket managed node group spanning the
    // cluster's private subnets across multiple Availability Zones.
    const hardenedNodegroup = cluster.addNodegroupCapacity('Hardened', {
      nodegroupName: `${prefix}-ng-build`,
      nodeRole,
      subnets: clusterSubnets,
      amiType: eks.NodegroupAmiType.BOTTLEROCKET_X86_64,
      instanceTypes: [ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.XLARGE)],
      minSize: 2,
      desiredSize: 2,
      maxSize: 5,
      launchTemplateSpec: {
        id: nodeLaunchTemplate.launchTemplateId!,
        version: nodeLaunchTemplate.latestVersionNumber,
      },
    });

    // Mirrors public.ecr.aws/* into <account>.dkr.ecr.<region>.amazonaws.com/ecr-public/*
    // on first pull. Public ECR needs no upstream credential secret.
    new ecr.CfnPullThroughCacheRule(this, 'EcrPublicPullThroughCache', {
      ecrRepositoryPrefix: 'ecr-public',
      upstreamRegistryUrl: 'public.ecr.aws',
    });

    // Lets the node role satisfy ECR pull-through cache requests (creating the
    // local mirror repo + importing the image) against a public upstream registry.
    hardenedNodegroup.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'EcrPullThroughCache',
      actions: ['ecr:BatchImportUpstreamImage', 'ecr:CreateRepository'],
      resources: ['*'],
    }));

    // DP-8 (persistent volumes): EBS CSI driver via EKS Pod Identity plus an
    // encrypted gp3 default StorageClass. Pod Identity keeps the driver's AWS
    // permissions off the node instance role (IAM-4).
    const podIdentityAgent = new eks.CfnAddon(this, 'PodIdentityAgentAddon', {
      clusterName: cluster.clusterName,
      addonName: 'eks-pod-identity-agent',
      resolveConflicts: 'OVERWRITE',
    });

    const ebsCsiRole = new iam.Role(this, 'EbsCsiDriverRole', {
      assumedBy: new iam.ServicePrincipal('pods.eks.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonEBSCSIDriverPolicy'),
      ],
      description: 'EKS Pod Identity role for the aws-ebs-csi-driver',
    });
    // Pod Identity trust requires sts:TagSession in addition to sts:AssumeRole.
    ebsCsiRole.assumeRolePolicy?.addStatements(new iam.PolicyStatement({
      actions: ['sts:TagSession'],
      principals: [new iam.ServicePrincipal('pods.eks.amazonaws.com')],
    }));

    const ebsCsiAddon = new eks.CfnAddon(this, 'EbsCsiDriverAddon', {
      clusterName: cluster.clusterName,
      addonName: 'aws-ebs-csi-driver',
      resolveConflicts: 'OVERWRITE',
      podIdentityAssociations: [{
        serviceAccount: 'ebs-csi-controller-sa',
        roleArn: ebsCsiRole.roleArn,
      }],
    });
    ebsCsiAddon.addResourceDependency(podIdentityAgent);

    // Encrypted gp3 default StorageClass for dynamically provisioned PVs.
    const encryptedStorageClass = cluster.addManifest('EncryptedGp3StorageClass', {
      apiVersion: 'storage.k8s.io/v1',
      kind: 'StorageClass',
      metadata: {
        name: 'gp3-encrypted',
        annotations: { 'storageclass.kubernetes.io/is-default-class': 'true' },
      },
      provisioner: 'ebs.csi.aws.com',
      parameters: {
        type: 'gp3',
        encrypted: 'true',
        kmsKeyId: nodeStorageKey.keyArn,
      },
      volumeBindingMode: 'WaitForFirstConsumer',
      allowVolumeExpansion: true,
    });
    encryptedStorageClass.node.addDependency(ebsCsiAddon);

    // Cluster Autoscaler for the hardened node group: scales the managed
    // node group's ASG (auto-discovered via the k8s.io/cluster-autoscaler/*
    // tags EKS applies to every managed node group's ASG automatically) in
    // response to unschedulable/underutilized pods. Auth via EKS Pod Identity
    // (IAM-4), matching the ebs-csi-driver pattern above.
    const clusterAutoscalerRole = new iam.Role(this, 'ClusterAutoscalerRole', {
      assumedBy: new iam.ServicePrincipal('pods.eks.amazonaws.com'),
      description: 'EKS Pod Identity role for the Kubernetes Cluster Autoscaler',
    });
    clusterAutoscalerRole.assumeRolePolicy?.addStatements(new iam.PolicyStatement({
      actions: ['sts:TagSession'],
      principals: [new iam.ServicePrincipal('pods.eks.amazonaws.com')],
    }));
    // The condition key itself embeds the (deploy-time-resolved) cluster name,
    // so it can't be a plain object key (CDK needs a string, not a token, for
    // map keys) — CfnJson defers that resolution to deployment time.
    const clusterAutoscalerTagCondition = new cdk.CfnJson(this, 'ClusterAutoscalerTagCondition', {
      value: {
        'aws:ResourceTag/k8s.io/cluster-autoscaler/enabled': 'true',
        [`aws:ResourceTag/k8s.io/cluster-autoscaler/${cluster.clusterName}`]: 'owned',
      },
    });
    clusterAutoscalerRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'ClusterAutoscalerScaling',
      actions: ['autoscaling:SetDesiredCapacity', 'autoscaling:TerminateInstanceInAutoScalingGroup'],
      resources: ['*'],
      conditions: {
        StringEquals: clusterAutoscalerTagCondition,
      },
    }));
    clusterAutoscalerRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'ClusterAutoscalerDescribe',
      actions: [
        'autoscaling:DescribeAutoScalingGroups',
        'autoscaling:DescribeAutoScalingInstances',
        'autoscaling:DescribeLaunchConfigurations',
        'autoscaling:DescribeScalingActivities',
        'autoscaling:DescribeTags',
        'ec2:DescribeImages',
        'ec2:DescribeInstanceTypes',
        'ec2:DescribeLaunchTemplateVersions',
        'ec2:GetInstanceTypesFromInstanceRequirements',
        'eks:DescribeNodegroup',
      ],
      resources: ['*'],
    }));

    const clusterAutoscalerPodIdentity = new eks.CfnPodIdentityAssociation(this, 'ClusterAutoscalerPodIdentity', {
      clusterName: cluster.clusterName,
      namespace: 'kube-system',
      serviceAccount: 'cluster-autoscaler',
      roleArn: clusterAutoscalerRole.roleArn,
    });
    clusterAutoscalerPodIdentity.addResourceDependency(podIdentityAgent);

    const clusterAutoscalerChart = new eks.HelmChart(this, 'ClusterAutoscaler', {
      cluster,
      chart: 'cluster-autoscaler',
      repository: 'https://kubernetes.github.io/autoscaler',
      namespace: 'kube-system',
      release: 'cluster-autoscaler',
      values: {
        autoDiscovery: { clusterName: cluster.clusterName },
        awsRegion: this.region,
        cloudProvider: 'aws',
        image: { repository: props.clusterAutoscalerImageRepository ?? 'registry.k8s.io/autoscaling/cluster-autoscaler', tag: props.clusterAutoscalerImageTag ?? 'v1.35.0' },
        rbac: {
          serviceAccount: {
            create: true,
            name: 'cluster-autoscaler',
            // Pod Identity matches on namespace + service account name; no IRSA
            // OIDC annotation needed.
            annotations: {},
          },
        },
        extraArgs: {
          // Only touch this cluster's own node group; the ASG tag condition
          // above is a second, IAM-enforced guardrail against cross-cluster writes.
          'balance-similar-node-groups': true,
        },
      },
    });
    clusterAutoscalerChart.node.addDependency(clusterAutoscalerPodIdentity);

    // Helm release names must be lowercase RFC 1123 DNS-1123 labels, so the
    // mixed-case stack name ('HarnessBuildFarm') can't be used directly. The
    // chart names the delegate's ServiceAccount after the release.
    const delegateName = this.stackName.toLowerCase();
    const delegateNamespace = 'harness-delegate';
    const delegateTokenK8sSecret = 'harness-delegate-token';
    // Builds run in a separate namespace so the delegate's pod/secret permissions
    // never apply in the namespace that holds the delegate pod and its token
    // secret. Point the Harness CI Kubernetes build infrastructure at this namespace.
    const buildNamespace = 'harness-builds';
    // The chart requires a permissions type; a custom name switches it off
    // cluster-admin. The delegate needs nothing where it runs, so it is bound to
    // an empty Role in its own namespace.
    const delegateSelfRoleName = 'harness-delegate-self';
    // Scoped Role for running build pods, applied only in the build namespace.
    const buildRoleName = 'harness-delegate-build';

    // INFRA-6: enforce Pod Security Standards on the workload namespaces
    // (warn/audit mirror enforce so violations are also surfaced).
    const pssLabels = (level: 'restricted' | 'baseline' | 'privileged') => ({
      'pod-security.kubernetes.io/enforce': level,
      'pod-security.kubernetes.io/enforce-version': 'latest',
      'pod-security.kubernetes.io/warn': level,
      'pod-security.kubernetes.io/warn-version': 'latest',
      'pod-security.kubernetes.io/audit': level,
      'pod-security.kubernetes.io/audit-version': 'latest',
    });
    // The delegate pod is fully restricted-compliant.
    const restrictedPssLabels = pssLabels('restricted');
    // Build pods run under the `privileged` PSS level, which effectively turns
    // off PSS admission for this namespace. The "Build and Push to Docker
    // Registry" step runs a Docker-in-Docker daemon (privileged: true), which
    // baseline blocks; PSS is namespace-scoped and cannot grant a per-container
    // exception, so the whole namespace has to be relaxed to the level the most
    // demanding step needs. This is an acceptable trade because harness-builds is
    // an isolated CI sandbox — separate namespace, scoped RBAC (no access to the
    // delegate pod or its token secret), NetworkPolicy, and node hardening remain
    // the real controls, not in-namespace PSS.
    //
    // NOTE: `baseline` already ALLOWS running as root (it only blocks privileged
    // containers, host namespaces, hostPath, etc.). If the failing step turns out
    // to need only UID 0 and not a privileged container, revert this to
    // pssLabels('baseline') — see the securityContext check in the deploy notes.
    const buildPssLabels = pssLabels('privileged');

    // Earlier deploys let the helm chart create this namespace
    // (createNamespace: true), so it already exists. overwrite makes the applier
    // use `kubectl apply` to adopt/relabel it instead of `kubectl create`, which
    // would fail with "namespaces already exists".
    const delegateNs = new eks.KubernetesManifest(this, 'HarnessDelegateNamespace', {
      cluster,
      overwrite: true,
      manifest: [{
        apiVersion: 'v1',
        kind: 'Namespace',
        metadata: { name: delegateNamespace, labels: { ...tags, ...restrictedPssLabels } },
      }],
    });

    // IAM-4/5/6: dedicated, scoped AWS identity for the delegate via EKS Pod
    // Identity so any AWS API calls made from build workloads use this role
    // rather than the worker node instance role. Starts with no permissions;
    // attach the minimum policies each pipeline needs here (explicit ARNs, no
    // wildcards) instead of granting the node role.
    const delegateWorkloadRole = new iam.Role(this, 'HarnessDelegateWorkloadRole', {
      assumedBy: new iam.ServicePrincipal('pods.eks.amazonaws.com'),
      description: 'Least-privilege EKS Pod Identity role for the Harness delegate service account',
    });
    delegateWorkloadRole.assumeRolePolicy?.addStatements(new iam.PolicyStatement({
      actions: ['sts:TagSession'],
      principals: [new iam.ServicePrincipal('pods.eks.amazonaws.com')],
    }));

    const delegatePodIdentity = new eks.CfnPodIdentityAssociation(this, 'HarnessDelegatePodIdentity', {
      clusterName: cluster.clusterName,
      namespace: delegateNamespace,
      serviceAccount: delegateName,
      roleArn: delegateWorkloadRole.roleArn,
    });
    delegatePodIdentity.addResourceDependency(podIdentityAgent);

    const delegateChart = new eks.HelmChart(this, 'HarnessDelegate', {
      cluster: cluster,
      chart: 'harness-delegate-ng',
      repository: 'https://app.harness.io/storage/harness-download/delegate-helm-chart/',
      namespace: delegateNamespace,
      // The namespace is created (and PSS-labelled) by the manifest above.
      createNamespace: false,
      release: delegateName,
      values: {
        delegateName: delegateName,
        // IAM-3: a custom name switches the chart from a cluster-admin
        // ClusterRoleBinding to a namespaced RoleBinding against this Role.
        k8sPermissionsType: delegateSelfRoleName,
        tags: `aws,eks,build-farm,${this.stackName}`,
        accountId: props.harnessAccountId,
        // With a secret name, the token comes from the ESO-synced Kubernetes secret.
        ...(props.harnessDelegateTokenSecretName
          ? { existingDelegateToken: delegateTokenK8sSecret }
          : { delegateToken: props.harnessDelegateToken }),
        managerEndpoint: props.harnessManagerEndpoint,
        delegateDockerImage: props.harnessDelegateImage,
        replicas: 1,
        // Upgrader disabled: the delegate image is managed declaratively via the
        // pinned delegateDockerImage above. Leaving the in-cluster upgrader on
        // makes it take server-side-apply ownership of the Deployment's image
        // field, which conflicts with every subsequent `helm upgrade` CDK runs.
        upgrader: {
          enabled: false,
        },
        // INFRA-6: make the delegate pod compliant with the `restricted` Pod
        // Security Standard enforced on its namespace (otherwise it is admitted
        // now but rejected on the next restart). The chart only emits a
        // container securityContext when the (deprecated, misleadingly named)
        // top-level `securityContext.runAsRoot` flag is truthy — it is really
        // the on-switch for the block — and prefers `delegateSecurityContext`
        // over `delegate.securityContext` when both are set.
        securityContext: {
          runAsRoot: true,
        },
        // Container securityContext (restricted-compliant). Note: forcing the
        // delegate off root (runAsUser 0 is the chart default) may break the
        // image if it needs to write to root-owned paths — verify the pod
        // actually reaches Ready after deploy.
        delegateSecurityContext: {
          runAsNonRoot: true,
          runAsUser: 1000,
          allowPrivilegeEscalation: false,
          capabilities: { drop: ['ALL'] },
          seccompProfile: { type: 'RuntimeDefault' },
        },
        // Pod-level securityContext (restricted-compliant); overrides the
        // chart default of only fsGroup: 1001.
        delegate: {
          pod: {
            securityContext: {
              runAsNonRoot: true,
              runAsUser: 1000,
              fsGroup: 1000,
              seccompProfile: { type: 'RuntimeDefault' },
            },
          },
        },
      },
    });
    delegateChart.node.addDependency(delegateNs);

    // Empty Role the chart's RoleBinding targets in the delegate namespace: the
    // delegate gets no rights over its own pod, token secret, or anything else
    // where it runs.
    const delegateSelfRole = cluster.addManifest('HarnessDelegateSelfRole', {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'Role',
      metadata: {
        name: delegateSelfRoleName,
        namespace: delegateNamespace,
      },
      rules: [],
    });
    delegateSelfRole.node.addDependency(delegateNs);

    // Dedicated namespace for build pods, isolated from the delegate.
    const buildNs = cluster.addManifest('HarnessBuildNamespace', {
      apiVersion: 'v1',
      kind: 'Namespace',
      metadata: { name: buildNamespace, labels: { ...tags, ...buildPssLabels } },
    });

    // INFRA-5: the VPC CNI only enforces NetworkPolicy when its network policy
    // agent is enabled; adopt the default add-on to turn it on.
    new eks.CfnAddon(this, 'VpcCniAddon', {
      clusterName: cluster.clusterName,
      addonName: 'vpc-cni',
      resolveConflicts: 'OVERWRITE',
      configurationValues: JSON.stringify({ enableNetworkPolicy: 'true' }),
    });

    // Namespace guardrails applied at creation: ResourceQuota, LimitRange
    // defaults, default-deny NetworkPolicy (ingress + egress), DNS egress, plus
    // any namespace-specific allow policies.
    type NetpolRule = Record<string, unknown>;
    const nsName = (name: string) => ({ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': name } } });
    const guardNamespace = (
      id: string,
      ns: Construct,
      namespace: string,
      quota: Record<string, string>,
      allow: { ingress?: NetpolRule[]; egress?: NetpolRule[] },
    ) => {
      const policy = (name: string, spec: Record<string, unknown>) => ({
        apiVersion: 'networking.k8s.io/v1',
        kind: 'NetworkPolicy',
        metadata: { name, namespace },
        spec: { podSelector: {}, ...spec },
      });
      const m = cluster.addManifest(id,
        {
          apiVersion: 'v1',
          kind: 'ResourceQuota',
          metadata: { name: 'default-quota', namespace },
          spec: { hard: quota },
        },
        {
          // Defaults requests only: a default limit could OOM-kill DinD builds.
          apiVersion: 'v1',
          kind: 'LimitRange',
          metadata: { name: 'default-requests', namespace },
          spec: { limits: [{ type: 'Container', defaultRequest: { cpu: '100m', memory: '128Mi' } }] },
        },
        policy('default-deny', { policyTypes: ['Ingress', 'Egress'] }),
        policy('allow-dns', {
          policyTypes: ['Egress'],
          egress: [{
            to: [{ ...nsName('kube-system'), podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }],
            ports: [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }],
          }],
        }),
        ...(allow.ingress ? [policy('allow-ingress', { policyTypes: ['Ingress'], ingress: allow.ingress })] : []),
        ...(allow.egress ? [policy('allow-egress', { policyTypes: ['Egress'], egress: allow.egress })] : []),
      );
      m.node.addDependency(ns);
    };

    // ponytail: egress to 0.0.0.0/0 on fixed ports; narrow to Harness/registry CIDRs or an egress proxy if required.
    // Link-local excluded so pods cannot reach IMDS even if the hop limit is misconfigured.
    const anyIp = { ipBlock: { cidr: '0.0.0.0/0', except: ['169.254.0.0/16'] } };
    // EKS Pod Identity agent (node-local link-local address).
    const podIdentityEgress = { to: [{ ipBlock: { cidr: '169.254.170.23/32' } }], ports: [{ protocol: 'TCP', port: 80 }] };
    guardNamespace('HarnessDelegateGuardrails', delegateNs, delegateNamespace,
      { pods: '10', 'requests.cpu': '4', 'requests.memory': '8Gi' },
      {
        egress: [
          // Harness manager, AWS APIs, and the private EKS API endpoint.
          { to: [anyIp], ports: [{ protocol: 'TCP', port: 443 }] },
          // Delegate -> build pod lite-engine (20001).
          { to: [nsName(buildNamespace)], ports: [{ protocol: 'TCP', port: 20001 }] },
          podIdentityEgress,
        ],
      });
    guardNamespace('HarnessBuildGuardrails', buildNs, buildNamespace,
      { pods: '50', 'requests.cpu': '16', 'requests.memory': '48Gi' },
      {
        ingress: [{ from: [nsName(delegateNamespace)], ports: [{ protocol: 'TCP', port: 20001 }] }],
        egress: [{ to: [anyIp], ports: [80, 443, 22].map((port) => ({ protocol: 'TCP', port })) }],
      });

    // Delegate token: synced from Secrets Manager into the delegate namespace by
    // External Secrets Operator (Pod Identity, read-only on this one secret). The
    // admission webhook/cert-controller are off to keep the footprint small.
    if (props.harnessDelegateTokenSecretName) {
      const esoNamespace = 'external-secrets';
      const tokenSecret = secretsmanager.Secret.fromSecretNameV2(this, 'DelegateTokenSecret', props.harnessDelegateTokenSecretName);
      const esoRole = new iam.Role(this, 'ExternalSecretsRole', { assumedBy: new iam.ServicePrincipal('pods.eks.amazonaws.com') });
      esoRole.assumeRolePolicy?.addStatements(new iam.PolicyStatement({
        actions: ['sts:TagSession'],
        principals: [new iam.ServicePrincipal('pods.eks.amazonaws.com')],
      }));
      tokenSecret.grantRead(esoRole);
      const esoPodIdentity = new eks.CfnPodIdentityAssociation(this, 'ExternalSecretsPodIdentity', {
        clusterName: cluster.clusterName,
        namespace: esoNamespace,
        serviceAccount: 'external-secrets',
        roleArn: esoRole.roleArn,
      });
      esoPodIdentity.addResourceDependency(podIdentityAgent);

      const esoNs = cluster.addManifest('ExternalSecretsNamespace', {
        apiVersion: 'v1',
        kind: 'Namespace',
        metadata: { name: esoNamespace, labels: { ...tags, ...restrictedPssLabels } },
      });
      guardNamespace('ExternalSecretsGuardrails', esoNs, esoNamespace,
        { pods: '5', 'requests.cpu': '2', 'requests.memory': '2Gi' },
        { egress: [{ to: [anyIp], ports: [{ protocol: 'TCP', port: 443 }] }, podIdentityEgress] });

      const esoChart = new eks.HelmChart(this, 'ExternalSecrets', {
        cluster,
        chart: 'external-secrets',
        repository: 'https://charts.external-secrets.io',
        version: '2.12.0',
        namespace: esoNamespace,
        createNamespace: false,
        release: 'external-secrets',
        wait: true,
        values: {
          serviceAccount: { name: 'external-secrets' },
          webhook: { create: false },
          certController: { create: false },
        },
      });
      esoChart.node.addDependency(esoNs, esoPodIdentity);

      const tokenSync = cluster.addManifest('DelegateTokenSync',
        {
          apiVersion: 'external-secrets.io/v1',
          kind: 'SecretStore',
          metadata: { name: 'aws-secrets-manager', namespace: delegateNamespace },
          spec: { provider: { aws: { service: 'SecretsManager', region: this.region } } },
        },
        {
          apiVersion: 'external-secrets.io/v1',
          kind: 'ExternalSecret',
          metadata: { name: delegateTokenK8sSecret, namespace: delegateNamespace },
          spec: {
            refreshInterval: '15m',
            secretStoreRef: { name: 'aws-secrets-manager', kind: 'SecretStore' },
            target: { name: delegateTokenK8sSecret, creationPolicy: 'Owner' },
            data: [{ secretKey: 'DELEGATE_TOKEN', remoteRef: { key: props.harnessDelegateTokenSecretName } }],
          },
        },
      );
      tokenSync.node.addDependency(esoChart, delegateNs);
      delegateChart.node.addDependency(tokenSync);
    }

    // DP: images may only come from approved registries. Applies to every
    // namespace except system ones. Defaults to warn+audit so it can be rolled
    // out before enforcing. ponytail: CREATE only (UPDATE would block metadata
    // writes on pods already running a disallowed image).
    if (props.allowedImageRegistries?.length) {
      const policyName = 'allowed-image-registries';
      const policyManifest = cluster.addManifest('AllowedImageRegistriesPolicy',
        {
          apiVersion: 'admissionregistration.k8s.io/v1',
          kind: 'ValidatingAdmissionPolicy',
          metadata: { name: policyName },
          spec: {
            failurePolicy: 'Fail',
            matchConstraints: {
              resourceRules: [{ apiGroups: [''], apiVersions: ['v1'], operations: ['CREATE'], resources: ['pods'] }],
            },
            variables: [
              { name: 'registries', expression: JSON.stringify(props.allowedImageRegistries) },
              {
                name: 'images',
                expression:
                  '(object.spec.containers + (has(object.spec.initContainers) ? object.spec.initContainers : [])).map(c, c.image)',
              },
            ],
            validations: [{
              expression: 'variables.images.all(i, variables.registries.exists(r, i.startsWith(r)))',
              messageExpression: '"images must come from approved registries: " + variables.registries.join(", ")',
            }],
          },
        },
        {
          apiVersion: 'admissionregistration.k8s.io/v1',
          kind: 'ValidatingAdmissionPolicyBinding',
          metadata: { name: policyName },
          spec: {
            policyName,
            validationActions: props.enforceAllowedImageRegistries ? ['Deny', 'Audit'] : ['Warn', 'Audit'],
            matchResources: {
              namespaceSelector: {
                matchExpressions: [{
                  key: 'kubernetes.io/metadata.name',
                  operator: 'NotIn',
                  values: ['kube-system', 'kube-public', 'kube-node-lease', 'default'],
                }],
              },
            },
          },
        },
      );
      policyManifest.node.addDependency(cluster);
    }

    // Node runtime/observability add-ons.
    if (props.enableGuardDutyAgent) {
      new eks.CfnAddon(this, 'GuardDutyAgentAddon', {
        clusterName: cluster.clusterName,
        addonName: 'aws-guardduty-agent',
        resolveConflicts: 'OVERWRITE',
      });
    }

    // CloudWatch agent + Fluent Bit (Container Insights) via Pod Identity.
    const cloudWatchRole = new iam.Role(this, 'CloudWatchObservabilityRole', {
      assumedBy: new iam.ServicePrincipal('pods.eks.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy')],
    });
    cloudWatchRole.assumeRolePolicy?.addStatements(new iam.PolicyStatement({
      actions: ['sts:TagSession'],
      principals: [new iam.ServicePrincipal('pods.eks.amazonaws.com')],
    }));
    new eks.CfnAddon(this, 'CloudWatchObservabilityAddon', {
      clusterName: cluster.clusterName,
      addonName: 'amazon-cloudwatch-observability',
      resolveConflicts: 'OVERWRITE',
      podIdentityAssociations: [{ serviceAccount: 'cloudwatch-agent', roleArn: cloudWatchRole.roleArn }],
    }).addResourceDependency(podIdentityAgent);

    // ECR: KMS-encrypted, scan-on-push, immutable tags.
    if (props.ecrRepositoryNames?.length) {
      const ecrKey = new kms.Key(this, 'EcrKey', { enableKeyRotation: true, description: `KMS CMK for ECR repositories (${id})` });
      for (const name of props.ecrRepositoryNames) {
        new ecr.Repository(this, `Repo${name.replace(/[^A-Za-z0-9]/g, '')}`, {
          repositoryName: name,
          encryption: ecr.RepositoryEncryption.KMS,
          encryptionKey: ecrKey,
          imageScanOnPush: true,
          imageTagMutability: ecr.TagMutability.IMMUTABLE,
        });
      }
    }

    // Backups: EBS CSI volumes via DLM. ponytail: targets every EBS CSI volume
    // in the account/region (the driver's own tag); narrow with a per-cluster tag.
    const dlmRole = new iam.Role(this, 'DlmRole', {
      assumedBy: new iam.ServicePrincipal('dlm.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSDataLifecycleManagerServiceRole')],
    });
    new dlm.CfnLifecyclePolicy(this, 'EbsSnapshotPolicy', {
      description: `Daily snapshots of EBS CSI volumes for ${id}`,
      state: 'ENABLED',
      executionRoleArn: dlmRole.roleArn,
      policyDetails: {
        resourceTypes: ['VOLUME'],
        targetTags: [{ key: 'ebs.csi.aws.com/cluster', value: 'true' }],
        schedules: [{
          name: 'daily',
          copyTags: true,
          createRule: { interval: 24, intervalUnit: 'HOURS', times: ['05:00'] },
          retainRule: { count: props.ebsSnapshotRetentionCount ?? 7 },
        }],
      },
    });

    // Backups: Velero saves cluster state to an encrypted, versioned bucket (EBS
    // data is covered by DLM above, so Velero snapshots are off).
    if (props.enableVelero) {
      const veleroNamespace = 'velero';
      const backupKey = new kms.Key(this, 'BackupKey', { enableKeyRotation: true, description: `KMS CMK for Velero backups (${id})` });
      const backupBucket = new s3.Bucket(this, 'BackupBucket', {
        encryption: s3.BucketEncryption.KMS,
        encryptionKey: backupKey,
        bucketKeyEnabled: true,
        enforceSSL: true,
        versioned: true,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      });
      const veleroRole = new iam.Role(this, 'VeleroRole', { assumedBy: new iam.ServicePrincipal('pods.eks.amazonaws.com') });
      veleroRole.assumeRolePolicy?.addStatements(new iam.PolicyStatement({
        actions: ['sts:TagSession'],
        principals: [new iam.ServicePrincipal('pods.eks.amazonaws.com')],
      }));
      backupBucket.grantReadWrite(veleroRole);
      const veleroPodIdentity = new eks.CfnPodIdentityAssociation(this, 'VeleroPodIdentity', {
        clusterName: cluster.clusterName,
        namespace: veleroNamespace,
        serviceAccount: 'velero-server',
        roleArn: veleroRole.roleArn,
      });
      veleroPodIdentity.addResourceDependency(podIdentityAgent);

      const veleroNs = cluster.addManifest('VeleroNamespace', {
        apiVersion: 'v1',
        kind: 'Namespace',
        metadata: { name: veleroNamespace, labels: { ...tags, ...pssLabels('baseline') } },
      });
      guardNamespace('VeleroGuardrails', veleroNs, veleroNamespace,
        { pods: '10', 'requests.cpu': '2', 'requests.memory': '4Gi' },
        { egress: [{ to: [anyIp], ports: [{ protocol: 'TCP', port: 443 }] }, podIdentityEgress] });

      const veleroChart = new eks.HelmChart(this, 'Velero', {
        cluster,
        chart: 'velero',
        repository: 'https://vmware-tanzu.github.io/helm-charts',
        version: '12.2.0',
        namespace: veleroNamespace,
        createNamespace: false,
        release: 'velero',
        values: {
          serviceAccount: { server: { name: 'velero-server' } },
          credentials: { useSecret: false },
          snapshotsEnabled: false,
          initContainers: [{
            name: 'velero-plugin-for-aws',
            image: props.veleroPluginImage ?? 'velero/velero-plugin-for-aws:v1.14.4',
            volumeMounts: [{ mountPath: '/target', name: 'plugins' }],
          }],
          configuration: {
            backupStorageLocation: [{
              name: 'default',
              provider: 'aws',
              bucket: backupBucket.bucketName,
              prefix: 'velero',
              config: { region: this.region },
            }],
          },
          schedules: {
            daily: { schedule: '0 6 * * *', template: { ttl: '168h0m0s', includedNamespaces: ['*'] } },
          },
        },
      });
      veleroChart.node.addDependency(veleroNs, veleroPodIdentity);
    }

    // IAM-3: least-privilege Role for running build pods, plus a RoleBinding for
    // the delegate SA (which lives in the delegate namespace). The delegate
    // discovers a build pod's IP via these pod reads and then connects to its
    // lite-engine on TCP 20001 directly over the pod network — no extra rights.
    const buildRole = cluster.addManifest('HarnessDelegateBuildRole', {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'Role',
      metadata: {
        name: buildRoleName,
        namespace: buildNamespace,
      },
      rules: [
        {
          apiGroups: [''],
          // configmaps: the delegate creates/deletes a per-build `*-common-env`
          // ConfigMap for each CI pod (CIK8CleanupTaskHandler.deleteCommonEnvConfigMaps).
          resources: ['pods', 'secrets', 'configmaps'],
          verbs: ['create', 'get', 'list', 'watch', 'update', 'delete'],
        },
        {
          apiGroups: [''],
          resources: ['events'],
          verbs: ['list', 'watch'],
        },
      ],
    });
    buildRole.node.addDependency(buildNs);

    const buildRoleBinding = cluster.addManifest('HarnessDelegateBuildRoleBinding', {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'RoleBinding',
      metadata: {
        name: `${buildRoleName}-binding`,
        namespace: buildNamespace,
      },
      subjects: [
        {
          kind: 'ServiceAccount',
          name: delegateName,
          namespace: delegateNamespace,
        },
      ],
      roleRef: {
        kind: 'Role',
        name: buildRoleName,
        apiGroup: 'rbac.authorization.k8s.io',
      },
    });
    buildRoleBinding.node.addDependency(buildRole);
    buildRoleBinding.node.addDependency(delegateChart);

    // INFRA-3: allow approved security groups (e.g. a self-hosted NAT/bastion)
    // to reach the private API server on 443. cluster.connections is the
    // control-plane security group attached to the API server ENIs.
    for (const sgId of props.apiServerIngressSecurityGroupIds ?? []) {
      cluster.connections.allowFrom(
        ec2.SecurityGroup.fromSecurityGroupId(this, `ApiServerIngress-${sgId}`, sgId),
        ec2.Port.tcp(443),
        `Allow HTTPS to the EKS API server from ${sgId}`,
      );
    }

    // IAM-1: grant approved IAM roles cluster access via EKS access entries
    // (authentication mode is API — there is no aws-auth ConfigMap).
    for (const roleArn of props.clusterAdminRoleArns ?? []) {
      const suffix = (roleArn.split('/').pop() ?? roleArn).replace(/[^A-Za-z0-9]/g, '');
      cluster.grantAccess(`ClusterAdminAccess-${suffix}`, roleArn, [
        eks.AccessPolicy.fromAccessPolicyName('AmazonEKSClusterAdminPolicy', {
          accessScopeType: eks.AccessScopeType.CLUSTER,
        }),
      ]);
    }

    // IAM/ABAC: persona-based access entries scoped to the app namespaces (the
    // ABAC aws:PrincipalTag conditions live on the federated roles themselves,
    // outside this stack). Namespace-scoped policies cannot create namespaces.
    const env = props.environment;
    const appNamespaces = [delegateNamespace, buildNamespace];
    const personaPolicy = {
      engineer: env === 'prod' ? undefined : env === 'dev' ? 'AmazonEKSAdminPolicy' : 'AmazonEKSViewPolicy',
      devops: 'AmazonEKSEditPolicy',
      // View policy has no pods/exec, so support cannot exec in any environment.
      support: 'AmazonEKSViewPolicy',
      breakglass: 'AmazonEKSClusterAdminPolicy',
    };
    const breakGlassRoleNames: string[] = [];
    for (const { persona, roleArn } of props.accessEntries ?? []) {
      const policy = personaPolicy[persona];
      const roleName = roleArn.split('/').pop() ?? roleArn;
      if (!policy) {
        cdk.Annotations.of(this).addWarning(`No ${persona} access in ${env}; skipping ${roleName}`);
        continue;
      }
      const clusterWide = persona === 'breakglass';
      new eks.CfnAccessEntry(this, `AccessEntry-${persona}-${roleName.replace(/[^A-Za-z0-9]/g, '')}`, {
        clusterName: cluster.clusterName,
        principalArn: roleArn,
        accessPolicies: [{
          policyArn: `arn:${this.partition}:eks::aws:cluster-access-policy/${policy}`,
          accessScope: clusterWide ? { type: 'cluster' } : { type: 'namespace', namespaces: appNamespaces },
        }],
        tags: [{ key: 'persona', value: persona }, { key: 'environment', value: env }],
      });
      if (clusterWide) breakGlassRoleNames.push(roleName);
    }

    // LOG-8/9: turn the EKS control-plane audit log into actionable alarms.
    // Metric filters over the audit stream feed CloudWatch alarms that notify an
    // SNS topic. Account-level detection (GuardDuty, CloudTrail, Security Hub) is
    // centralized in the org security account and handled there.
    const auditAlarmTopic = new sns.Topic(this, 'EksAuditAlarmTopic', {
      displayName: `${this.stackName} EKS audit alarms`,
    });
    if (props.alarmNotificationEmail) {
      auditAlarmTopic.addSubscription(
        new snsSubscriptions.EmailSubscription(props.alarmNotificationEmail),
      );
    }
    const alarmAction = new cloudwatchActions.SnsAction(auditAlarmTopic);

    // EKS creates this log group when control-plane logging is enabled (LOG-1);
    // reference it by name rather than declaring it so CDK does not try to own it.
    const auditLogGroup = logs.LogGroup.fromLogGroupName(
      this,
      'EksControlPlaneLogGroup',
      `/aws/eks/${cluster.clusterName}/cluster`,
    );

    const metricNamespace = `${this.stackName}/EKSAudit`;

    // Each entry becomes a metric filter over the audit log, a Sum metric, and an
    // alarm that fires on a single matching event in a 5-minute window. Missing
    // data is not breaching so quiet clusters stay green.
    const auditAlarms: Array<{
      id: string;
      metricName: string;
      description: string;
      filterPattern: string;
    }> = [
      {
        id: 'AuthorizationFailures',
        metricName: 'AuthorizationFailures',
        description: 'An API request was denied by RBAC (authorization decision = forbid).',
        // CloudWatch's JSON metric-filter selectors cannot reference a key
        // containing '.' or '/' (the decision lives under the annotation
        // "authorization.k8s.io/decision"), even when quoted. Match the exact
        // serialized substring instead — EKS audit events are compact JSON with
        // no space after the colon, verified against the live log group.
        filterPattern: String.raw`"\"authorization.k8s.io/decision\":\"forbid\""`,
      },
      {
        id: 'RbacChanges',
        metricName: 'RbacChanges',
        description: 'A (cluster)role or (cluster)rolebinding was created, updated, patched, or deleted.',
        filterPattern:
          '{ ($.verb = "create" || $.verb = "update" || $.verb = "patch" || $.verb = "delete") && ' +
          '($.objectRef.resource = "roles" || $.objectRef.resource = "rolebindings" || ' +
          '$.objectRef.resource = "clusterroles" || $.objectRef.resource = "clusterrolebindings") }',
      },
      {
        id: 'PodExecAttach',
        metricName: 'PodExecAttach',
        description: 'Someone opened an exec/attach session into a pod.',
        filterPattern:
          '{ ($.objectRef.resource = "pods") && ' +
          '($.objectRef.subresource = "exec" || $.objectRef.subresource = "attach") }',
      },
      {
        id: 'AnonymousRequests',
        metricName: 'AnonymousRequests',
        description: 'An unauthenticated (system:anonymous) request reached the API server.',
        filterPattern: '{ $.user.username = "system:anonymous" }',
      },
      {
        id: 'KubeSystemChanges',
        metricName: 'KubeSystemChanges',
        description: 'A write occurred to a resource in the kube-system namespace.',
        filterPattern:
          '{ ($.verb = "create" || $.verb = "update" || $.verb = "patch" || $.verb = "delete") && ' +
          '($.objectRef.namespace = "kube-system") }',
      },
    ];

    // Alert whenever a break-glass principal touches the API.
    breakGlassRoleNames.forEach((name, i) => auditAlarms.push({
      id: `BreakGlassUse${i}`,
      metricName: `BreakGlassUse${i}`,
      description: `Break-glass role ${name} was used.`,
      filterPattern: `{ $.user.username = "*assumed-role/${name}/*" }`,
    }));

    for (const spec of auditAlarms) {
      const metricFilter = new logs.MetricFilter(this, `${spec.id}MetricFilter`, {
        logGroup: auditLogGroup,
        metricNamespace,
        metricName: spec.metricName,
        filterPattern: logs.FilterPattern.literal(spec.filterPattern),
        metricValue: '1',
        defaultValue: 0,
      });
      // The imported log group carries no CFN dependency; ensure the cluster (and
      // thus the EKS-managed log group) exists before the filter is created.
      metricFilter.node.addDependency(cluster);

      const alarm = new cloudwatch.Alarm(this, `${spec.id}Alarm`, {
        alarmName: `${this.stackName}-${spec.metricName}`,
        alarmDescription: spec.description,
        metric: new cloudwatch.Metric({
          namespace: metricNamespace,
          metricName: spec.metricName,
          statistic: cloudwatch.Stats.SUM,
          period: cdk.Duration.minutes(5),
        }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      alarm.addAlarmAction(alarmAction);
    }

  }
}
