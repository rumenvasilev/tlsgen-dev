FROM scratch

COPY bin/tlsgen-dev /bin/tlsgen-dev

# Create Root CA
RUN ["/bin/tlsgen-dev", "-root"]

ENTRYPOINT ["/bin/tlsgen-dev"]