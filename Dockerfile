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

FROM golang:1.24.5-bookworm@sha256:ef8c5c733079ac219c77edab604c425d748c740d8699530ea6aced9de79aea40 as build
ARG GITHUB_REF_NAME

WORKDIR /go/src/app
COPY . .

RUN go mod download
ENV FLAGS="ldflags='-X main.release=devguard@${GITHUB_REF_NAME}'"
RUN CGO_ENABLED=0 make devguard
RUN CGO_ENABLED=0 make devguard-cli

FROM gcr.io/distroless/static-debian12@sha256:b7b9a6953e7bed6baaf37329331051d7bdc1b99c885f6dbeb72d75b1baad54f9

WORKDIR /

COPY config/rbac_model.conf /config/rbac_model.conf
COPY --from=build /go/src/app/devguard /usr/local/bin/devguard
COPY --from=build /go/src/app/devguard-cli /usr/local/bin/devguard-cli
COPY templates /templates
COPY intoto-public-key.pem /intoto-public-key.pem
COPY cosign.pub /cosign.pub

CMD ["devguard"]