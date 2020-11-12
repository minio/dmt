# Direct MinIO Tunnel

## Usage `dmt`

```
Usage of ./dmt:
  -ca-cert string
        CA certificates (default "/etc/dmt/ca.crt")
  -tls-cert string
        TLS certificate (default "/etc/dmt/tls.crt")
  -tls-key string
        TLS key (default "/etc/dmt/tls.key")
```

## Docker

For development and local testing you can build new docker image via `make`

```$bash
TAG=minio/dmt:dev make docker
```

## Kubernetes

When deploying to `kubernetes`, `dmt` requires a configmap with the name `dmt-config` to exists in the same namespace `dmt` is running, you can create the configmap using the following commands:

```$bash
echo "{\"version\": \"1\", \"routes\": {}}" > routes.json
kubectl creat cm dmt-config --from-file=routes.json
```

Additionally, `TLS` for `dmt` server is mandatory, make sure certificate secrets exists in the same namespace `dmt` is running, ie

```$bash
kubectl create secret generic dmt-certs --from-file=public.crt --from-file=private.key --from-file=ca.crt
```

Deploy `dmt`

```$bash
kubectl apply -f k8s/examples/dmt.yaml
```

Your application can start pushing k/v to the `dmt-config` configmap in JSON format and `dmt` will react to those changes via k8s informers.

### routes.json example

```json
{
    "version": "1",
    "routes": {
        "0HHZW0BSUIK3TGCF": "backend-1:9000",
        "1OIGLFDMYMWIJCFV": "backend-2:9000",
        "2S2UPSUO4L4XMTU0": "backend-3:9000",
        "4103GYZD1OFNTL3Y": "backend-4:9000",
        "4QW2BNRBPGSUP24Z": "backend-5:9000"
    }
}
```
