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
