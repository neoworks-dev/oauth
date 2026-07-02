module github.com/neoworks/oauth

go 1.26.4

require (
	github.com/go-chi/chi/v5 v5.2.5
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/joho/godotenv v1.5.1
	github.com/neoworks/auth v0.0.0-00010101000000-000000000000
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/surrealdb/surrealdb.go v1.4.0
	golang.org/x/crypto v0.51.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/gofrs/uuid v4.4.0+incompatible // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/lestrrat-go/blackmagic v1.0.3 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.1.6 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/redis/go-redis/v9 v9.18.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

replace github.com/neoworks/auth => ../api
