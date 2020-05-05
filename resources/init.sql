create table if not exists sessions
(
    token         character varying(50) not null,
    address       character varying(42) not null,
    nonce         character varying(50) not null,
    authenticated boolean               not null,
    timestamp     timestamptz           not null
);

create unique index if not exists sessions_token_unique_idx on sessions (lower(token));
create index if not exists sessions_token_timestamp_idx on sessions (timestamp) where not authenticated;

create or replace function start_session(p_version text,
                                         p_token text,
                                         p_address text,
                                         p_nonce text,
                                         p_timestamp timestamptz) RETURNS text
    language 'plpgsql'
as
$body$
begin
    insert into sessions (token, address, nonce, authenticated, timestamp)
    values (p_token, p_address, p_nonce, false, p_timestamp);
    return null;
exception
    when unique_violation then
        return 'duplicate token';
end
$body$;

create or replace function authenticate(p_version text,
                                        p_token text,
                                        p_address text,
                                        p_nonce text,
                                        p_timestamp timestamptz) RETURNS text
    language 'plpgsql'
as
$body$
declare
    l_authenticated boolean;
    l_address       text;
    l_nonce         text;
begin
    select authenticated, address, nonce
    into l_authenticated, l_address, l_nonce
    from sessions
    where lower(token) = lower(p_token)
        for update;

    if l_address is null or l_address <> p_address or l_nonce <> p_nonce then
        return 'no data found';
    end if;

    if l_authenticated then
        return 'already authenticated';
    end if;

    update sessions
    set authenticated = true,
        "timestamp"   = p_timestamp
    where lower(token) = lower(p_token);

    return null;
end
$body$;

create or replace function logout(p_version text,
                                  p_token text) RETURNS boolean
    language 'plpgsql'
as
$body$
declare
    l_token text;
begin
    delete from sessions where lower(token) = lower(p_token) and authenticated returning token into l_token;
    return l_token is not null;
end
$body$;