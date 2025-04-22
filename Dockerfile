# Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

FROM golang:1.24.2@sha256:d9db32125db0c3a680cfb7a1afcaefb89c898a075ec148fdc2f0f646cc2ed509 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 make devguard
RUN CGO_ENABLED=0 make devguard-cli

FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

WORKDIR /

COPY config/rbac_model.conf /config/rbac_model.conf
COPY --from=build /go/src/app/devguard /usr/local/bin/devguard
COPY --from=build /go/src/app/devguard-cli /usr/local/bin/devguard-cli
COPY templates /templates
COPY intoto-public-key.pem /intoto-public-key.pem
COPY cosign.pub /cosign.pub

CMD ["devguard"]