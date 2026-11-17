# The image nitro-cli turns into the nsm-check Enclave Image File.
#
# Build it with `make image` from the repository root. That compiles the
# binary first and passes the directory holding it as the build context.

FROM scratch AS base
ARG TARGETARCH
COPY nsm-check-${TARGETARCH} /nsm-check

# Also extends and locks PCRs. `make eif PCR_WRITES=1` selects this stage.
FROM base AS pcr-writes
CMD ["/nsm-check", "-pcr-writes"]

# The default: only the checks that read from the NSM.
FROM base AS read-only
CMD ["/nsm-check"]
