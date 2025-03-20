FROM golang:1.24.1 AS build
COPY . ./
RUN go build -o /bin/openuem-cert-manager .

FROM debian:latest
COPY --from=build /bin/openuem-cert-manager /bin/openuem-cert-manager
ENTRYPOINT ["/bin/openuem-cert-manager"]