FROM ghcr.io/edgelesssys/ego-dev:latest

WORKDIR /app
COPY sec_storage .
COPY enclave.json .

EXPOSE 8080

ENV OE_SIMULATION=1

CMD ["ego", "run", "sec_storage"]
