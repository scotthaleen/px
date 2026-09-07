-- +goose Up
CREATE TABLE context_stun_servers (
    context_name TEXT NOT NULL REFERENCES contexts(name) ON DELETE CASCADE,
    position INTEGER NOT NULL CHECK (position >= 0 AND position < 4),
    url TEXT NOT NULL,
    PRIMARY KEY (context_name, position),
    UNIQUE (context_name, url)
);

-- +goose Down
DROP TABLE context_stun_servers;
