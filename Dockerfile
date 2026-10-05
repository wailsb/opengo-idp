FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/idp ./cmd/idp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/idp /idp
EXPOSE 8080
ENTRYPOINT ["/idp"]
CMD ["serve"]
