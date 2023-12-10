FROM alpine

COPY bin /bin/

# Create Root CA
RUN /bin/tlsgen-dev --root

ENTRYPOINT /bin/tlsgen-dev