# Image du serveur AuxiPak (Debian 13 « trixie »).
# Aucune clé ni aucun secret n'est intégré à l'image : les clés sont montées
# en lecture seule à l'exécution (voir docker-compose.yml et docs/SIGNING.md).

FROM rust:1.97-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p auxipak-server -p auxipak-builder

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 auxipak \
 && useradd --system --uid 10001 --gid auxipak --home-dir /var/lib/auxipak-server --shell /usr/sbin/nologin auxipak \
 && mkdir -p /var/lib/auxipak-server /etc/auxipak-server/keys \
 && chown auxipak:auxipak /var/lib/auxipak-server
COPY --from=build /src/target/release/auxipak-server /usr/local/bin/auxipak-server
COPY --from=build /src/target/release/auxipak-builder /usr/local/bin/auxipak-builder
USER auxipak
ENV AUXIPAK_BIND=0.0.0.0:8080 \
    AUXIPAK_DATA_DIR=/var/lib/auxipak-server \
    AUXIPAK_KEYS_DIR=/etc/auxipak-server/keys
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/api/v1/health || exit 1
ENTRYPOINT ["/usr/local/bin/auxipak-server"]
CMD ["serve"]
