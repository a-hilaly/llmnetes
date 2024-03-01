# LLM*NETES

Bringing LLM's to Kubernetes.

<p align="center">
<img src="./docs/images/llmnetes-cute-astronaut.jpg" width="250" >
</p>

Disclaimer: This project is still work in progress and is not ready 
for production use.

## Description

Introducing LLMNETES, a Kubernetes controller designed to simplify
cluster management with a natural language interface. Powered by
Large Language Models (LLM).

Whether it's creating deployments, deleting pods, or triggering chaos
experiments, LLMNETES understands and tries executes your commands
efficiently. It currently supports multiple LLM backends, including
**OpenAI's**  **GPT-3** and a local model trained on a dataset.
Additionally, users  can integrate their own LLM backend by
implementing the provided LLM interface.

## Support table

| LLM backend | Supported | Notes |
| ----------- | --------- | ----- |
| OpenAI GPT-X | Yes | |
| llama local model | WIP | |

## Installation

### Prerequisites

- A Kubernetes cluster
- [helm](https://helm.sh/docs/intro/install/) installed and configured to access your cluster
- An OPENAI API key

```bash
helm install --create-namespace \
    llmnetes oci://ghcr.io/llmnetes/llmnetes \
    --version "0.0.1" \
    --set=backned.openai.apiKey=<your-open-ai-key> \
    --set=backend.customLLM.svc=
```

## Examples

#### Create a deployment with 3 replicas

To deploy new pods using llmnetes, you can deploy the following manifest:

```yaml
apiVersion: llmnetes.dev/v1alpha1
kind: Command
metadata:
  name: my-command
spec:
  input: Create 3 nginx pods that will serve traffic on port 80.
```

This will create 3 nginx pods that will serve traffic on port 80.

#### Chaos experiments

llmnetes can also be used to trigger chaos experiments. For example, to kill a pod in the default namespace, you can deploy the following manifest:

```yaml
apiVersion: llmnetes.dev/v1alpha1
kind: ChaosSimulation
metadata:
  name: chaos-simulation-cr
spec:
  level: 10
  command: break my cluster networking layer (or at least try to)
```

## License

Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

