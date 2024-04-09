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

FROM golang:1.21.6 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/app cmd/flawfix/main.go
RUN CGO_ENABLED=0 go build -o /go/bin/flawfix-cli cmd/flawfix-cli/main.go

FROM gcr.io/distroless/static-debian11

COPY config/rbac_model.conf /config/rbac_model.conf
COPY --from=build /go/bin/app /
COPY --from=build /go/bin/flawfix-cli /

CMD ["/app"]