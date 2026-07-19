FROM alpine:3.24 AS builder
RUN apk add --no-cache gcc musl-dev make
WORKDIR /src
COPY . ./
RUN make clean all STATIC=1

FROM alpine:3.24
COPY --from=builder /src/linx /linx
USER 65534:65534
ENTRYPOINT ["/linx"]
