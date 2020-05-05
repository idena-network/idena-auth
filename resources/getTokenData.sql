select address, nonce, authenticated, "timestamp"
from sessions
where lower(token) = lower($1);