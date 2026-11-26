FROM rust:1-alpine AS build
ENV CARGO_BUILD_JOBS=2 CARGO_PROFILE_RELEASE_LTO=false
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p authlens-lab

FROM alpine:3.21
WORKDIR /app
COPY --from=build /src/target/release/authlens-lab /app/authlens-lab
COPY web/dist /app/web/dist
ENV AUTHLENS_WEB_DIST=/app/web/dist
USER 10001:10001
EXPOSE 3000 8080-8087
CMD ["/app/authlens-lab"]
