FROM node:22-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git git-lfs \
    && rm -rf /var/lib/apt/lists/* \
    && git lfs install --system

# Install the command-line scanners used by repository generation and
# vulnerability analysis. Their official installers choose the correct CPU
# architecture for the Railway runtime image.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sh -s -- -b /usr/local/bin \
    && syft version \
    && grype version

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build /app/dist ./dist

RUN mkdir -p /app/.sbom-validation

ENV NODE_ENV=production \
    PORT=8080 \
    SYFT_BIN=/usr/local/bin/syft \
    GRYPE_BIN=/usr/local/bin/grype \
    SBOM_VALIDATION_WORKDIR=/app/.sbom-validation

EXPOSE 8080

CMD ["npm", "start"]
