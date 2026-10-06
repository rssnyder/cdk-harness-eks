# cdk harness eks

provision a secure eks cluster with a harness delegate to serve as a harness build farm.

due to the heightened security baseline of this cluster, there are certain settings that are needed on the harness stage and individual step to allow build pods to be provisioned and executed.

stage infra:
```
              containerSecurityContext:
                capabilities:
                  drop:
                    - ALL
                privileged: false
                allowPrivilegeEscalation: false
                runAsNonRoot: true
                runAsUser: "1000"
```

step example:
```
              - step:
                  type: Run
                  name: Run_1
                  identifier: Run_1
                  spec:
                    connectorRef: account.buildfarm_container_registry_cloud
                    image: busybox
                    shell: Sh
                    command: echo hello
                    privileged: false

```

## architecture

```
AWS Account 664418987337  ·  us-west-2
└─ VPC (imported)  ·  PRIVATE_ISOLATED subnets, multi-AZ

┌────────────────────────────────────────────────────────────────────────────────────┐
│ EKS Cluster  ·  Kubernetes v1.36                                                   │
├────────────────────────────────────────────────────────────────────────────────────┤
│ private-only API server endpoint ......................... [INFRA-1]               │
│ secrets envelope encryption w/ CMK EksSecretsKey ......... [DP-7]                  │
│ all 5 control-plane log types enabled .................... [LOG-1]                 │
│ IAM authentication mode = API + access entries ........... [IAM-1]                 │
│ API-server security-group ingress: approved SGs only ..... [INFRA-3]               │
└────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────────┐
│ Managed Node Group  "Hardened"                                                     │
├────────────────────────────────────────────────────────────────────────────────────┤
│ Bottlerocket AMI, 2-5 nodes, spans multiple AZs .......... [INFRA-4/RES-1]         │
│ Launch Template: IMDSv2 required, hop-limit 1 ............ [IAM-8]                 │
│ Launch Template: EBS volumes encrypted w/ CMK ........... [DP-8]                   │
└────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────────┐
│ EKS Pod Identity  &  Storage                                                       │
├────────────────────────────────────────────────────────────────────────────────────┤
│ eks-pod-identity-agent addon                                                       │
│ EBS CSI driver addon + scoped IAM role ................... [IAM-4]                 │
│ Harness delegate workload role (least-privilege) ........ [IAM-4/5/6]              │
│ gp3-encrypted default StorageClass w/ CMK ............... [DP-8]                   │
└────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────────┐
│ Namespace: harness-delegate                                                        │
├────────────────────────────────────────────────────────────────────────────────────┤
│ Pod Security Standard enforce = restricted ............... [INFRA-6]               │
│ Harness Delegate Deployment: restricted-compliant pod,                             │
│   runAsNonRoot uid 1000 ................................. [INFRA-6]                │
│ self Role = empty + namespaced RoleBinding (no rights) ... [IAM-3]                 │
└────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────────┐
│ Namespace: harness-builds                                                          │
├────────────────────────────────────────────────────────────────────────────────────┤
│ Pod Security Standard enforce = privileged .............. [INFRA-6]                │
│ ephemeral CI build pods (created by the delegate)                                  │
│ build Role: pods/secrets/configmaps/events .............. [IAM-3]                  │
│ RoleBinding -> delegate SA (cross-namespace) ............ [IAM-3]                  │
└────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────────┐
│ Observability                                                                      │
├────────────────────────────────────────────────────────────────────────────────────┤
│ control-plane audit log group ........................... [LOG-1]                  │
│ 5 metric filters + alarms ............................... [LOG-8/9]                │
│   AuthorizationFailures, RbacChanges, PodExecAttach,                               │
│   AnonymousRequests, KubeSystemChanges                                             │
│ SNS topic -> email subscription ......................... [LOG-8/9]                │
└────────────────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────────────────┐
│ KMS  (customer-managed, auto-rotated)                                              │
├────────────────────────────────────────────────────────────────────────────────────┤
│ EksSecretsKey  - Kubernetes secret encryption ........... [DP-7]                   │
│ NodeStorageKey - node & EBS volume encryption ........... [DP-8]                   │
└────────────────────────────────────────────────────────────────────────────────────┘

legend (controls, see SECURITY_GUARDRAILS.md):
  DP-7 / DP-8       KMS envelope encryption of secrets / node & EBS volumes
  INFRA-1 / 3 / 4 / 6   private API endpoint / SG ingress / hardened nodes / Pod Security
  IAM-1 / 3 / 4 / 5 / 6 / 8   IAM access entries / scoped RBAC / Pod Identity least-priv / IMDSv2
  LOG-1 / 8 / 9     control-plane logging / audit metric filters / alarms + notification
  RES-1             multi-AZ node group
```
