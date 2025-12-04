# Copyright (C) 2024 Tim Bastin, l3montree GmbH
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

FROM golang:1.25.5-trixie@sha256:4f9d98ebaa759f776496d850e0439c48948d587b191fc3949b5f5e4667abef90 AS golang-builder

ARG GITHUB_SHA
ARG GITHUB_REF_NAME

ENV GITHUB_REF_NAME=${GITHUB_REF_NAME}
ENV GITHUB_SHA=${GITHUB_SHA}

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 make devguard
RUN CGO_ENABLED=0 make devguard-cli

FROM registry.opencode.de/open-code/oci/static:latest@sha256:cb21f441936c41b2f2fec8f29a10f2e9b8cb32ab3530e78e33a34479d4fa177d

USER 53111

WORKDIR /app

COPY --chown=53111:53111 config/rbac_model.conf /app/config/rbac_model.conf
COPY --chown=53111:53111 --from=golang-builder /go/src/app/devguard /usr/local/bin/devguard
COPY --chown=53111:53111 --from=golang-builder /go/src/app/devguard-cli /usr/local/bin/devguard-cli
COPY --chown=53111:53111 intoto-public-key.pem /app/intoto-public-key.pem
COPY --chown=53111:53111 cosign.pub /app/cosign.pub

CMD ["devguard"]