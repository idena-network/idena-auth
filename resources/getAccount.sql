select address
from sessions
where lower(token) = lower($1)
  and authenticated