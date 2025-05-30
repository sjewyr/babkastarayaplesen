CREATE TABLE IF NOT EXISTS data_centers(
    id BIGINT IDENTITY,
    name VARCHAR(50),
    host VARCHAR(50),
    port INT
)