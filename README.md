# bliinks-idp

Identity provider and account management service for the bliinks network.

## Features

Here is a partial list of the features to give you a better idea of what this code does:

- Custom-spec OAuth2 API
- Session-based authentication
- SQLite database backend
- Tera templating
- Rate limiting and access control middleware
- CAPTCHA support via `yaptcha`
- Optional migration utility for legacy chatroom db

## Requirements

- [Rust](https://rustup.rs) toolchain
- SQLite

## Configuration

Example configuration (`config.toml` is a required file):

```toml
[server]
host = "127.0.0.1"
port = 3000

[general]
title = "example"
dev = true

[database]
url = "sqlite:./data.db?mode=rwc"
```

Or copy the provided example file:

```bash
cp example.toml config.toml
```

Please note: the default bind address is `127.0.0.1:3000`, which only allows local connections. To make the application accessible from other devices on your network or from a VM, change the IP to `0.0.0.0`.

### Sections

#### `[server]`

| Key | Description |
|---|---|
| `host` | Bind address |
| `port` | Listening port |

#### `[general]`

| Key | Description |
|---|---|
| `title` | Instance title |
| `dev` | Enables development mode |

#### `[database]`

| Key | Description |
|---|---|
| `url` | SQLite connection string |

## Building

```bash
cargo build --release
```

Release binaries will be placed in:

```text
target/release/
```

## Running

Run the application:

```bash
cargo run
```

Or run the release build:

```bash
./target/release/bliinks-idp
```

## Database

The project uses SQLite through SQLx.

Database files are created automatically if they do not exist.

## Manual Legacy Migration

An optional migration utility is included for importing legacy data from bliinks chatrooms.

Run it with:

```bash
cargo run --bin migrate_legacy ./path-to-sqlite.db ./path-to-data.json
```

Or from a release build:

```bash
./target/release/migrate_legacy
```

Note: This utility assumes you have a properly formatted JSON file containing entries of a specific format. If you are not sure what this is for, do not touch it. This migration is non-destructive and automatically deduplicated.

## Reverse Proxy Configuration

If running behind Nginx or another reverse proxy, remember to set the correct directives. The default file upload size used for profile pictures is 5 MB.

Example:

```nginx
set_real_ip_from <your_proxy_ip>;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
client_max_body_size 5m;
```

Replace or extend these settings as needed for your environment. For more information, check the `security_headers` method in `/src/middleware.rs`

## Contributing

Do not commit directly to the main branch. Open a pull request with a clear description of your changes.

When reporting a bug through GitHub issues, remember to include your browser version, and steps to reproduce the issue.

## Additional information

For additional information, such as integrating OAuth into your application, please see the `/docs` directory.

## License

MIT
