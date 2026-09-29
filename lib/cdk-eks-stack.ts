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
  readonly harnessDelegateToken: string;
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
}

export class CdkEksStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: CdkEksStackProps) {
    super(scope, id, props);

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', {
      vpcId: props.vpcId,
    });

    // DP-7: customer-managed key for KMS envelope encryption of Kubernetes secrets.
    const secretsKey = new kms.Key(this, 'EksSecretsKey', {
      enableKeyRotation: true,
      description: `KMS CMK for EKS Kubernetes secret envelope encryption (${id})`,
    });

    const clusterSubnets = { subnetType: ec2.SubnetType.PRIVATE_ISOLATED } // this is because I host my own NAT, more than likley you want PRIVATE_WITH_EGRESS or PRIVATE_WITH_NAT

    const cluster = new eks.Cluster(this, 'Cluster', {
      version: eks.KubernetesVersion.V1_36,
      // No default capacity — worker nodes come from the hardened Bottlerocket
      // managed node group defined below.
      defaultCapacity: 0,
      kubectlLayer: new KubectlV36Layer(this, 'kubectl'),
      vpc,
      vpcSubnets: [clusterSubnets], 

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
    const delegateNamespace = 'harness-delegate-ng';
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
        metadata: { name: delegateNamespace, labels: restrictedPssLabels },
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
        delegateToken: props.harnessDelegateToken,
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
      metadata: { name: buildNamespace, labels: buildPssLabels },
    });

    // IAM-3: least-privilege Role for running build pods, plus a RoleBinding for
    // the delegate SA (which lives in the delegate namespace). The delegate
    // discovers a build pod's IP via these pod reads and then connects to its
    // lite-engine on TCP 2001 directly over the pod network — no extra rights.
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
