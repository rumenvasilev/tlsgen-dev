# tlsgen-dev

Minimalistic certificate minting tool, to ease development of apps with mTLS security for authN/Z.
It is not intended for production use!

## Use case

You have a local (dev) k8s cluster and want to use your own certificates to secure communication between containers with mTLS. So you employ an init container (this), running before your application, but sharing a volume between the two. The init container creates new certificate/key pair, deposits that to the shared volume and exit. Then your main container starts, reads the shared volume and uses the TLS material to secure east/west (in-cluster) communication.

## How does it work

The root CA gets generated during docker build, so if you're pulling the image from the registry, it already has dev CA inside. Every new version has a new CA. It has 10 years of validity. If you want to use your own signing CA, make sure you mount it at start-up with a volume under `/tmp/tls/ca` with filenames `root.pem` and `root.key`.

The client/server certificate/key pair is generated upon container start (signed by the root CA). Then the container automatically exits. Resulting data is in `/tmp/tls/client`. That's the directory you'd want to have shared between your init and main containers. Preferrably as tmp in-memory volume. In case you're running outside kubernetes, just make sure that directory is mounted as volume to a host directory on your machine, so you can extract the generated data.

Private key is RSA with 2048 bits encryption. Certificate uses some generic information and SVID SAN (SPIFFE ID), you could use for authZ. It's validity is 4 hours.

## Caveats

SPIFFE ID is very basic - `spiffe://local.dev/<container-hostname>`, which means you need to examine the trust domain only. My intent is to add an additional enhanced format, to include more k8s specific metadata (like `namespace`), so then you can employ more granular authZ decisions.