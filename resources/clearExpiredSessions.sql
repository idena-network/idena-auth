delete
from sessions
where "timestamp" < $1
  and not authenticated