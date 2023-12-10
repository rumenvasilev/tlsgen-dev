# tlsgen-dev

Minimalistic certificate minting tool, to ease development of apps with mTLS security for authN/Z.
It is not intended for production use!

# Use case

You have a local (dev) k8s cluster and want to use your own certificates to secure communication between containers with mTLS. So you employ an init container (this), running before your application, but sharing a volume between the two. The init container creates new certificate/key pair, deposits that to the shared volume and exit. Then your main container starts, reads the shared volume and uses the TLS material to secure east/west (in-cluster) communication.

## Caveats

SPIFFE ID is very basic - `spiffe://local.dev/<container-hostname>`, which means you need to examine the trust domain only. My intent is to add an additional enhanced format, to include more k8s specific metadata (like `namespace`), so then you can employ more granular authZ decisions.
