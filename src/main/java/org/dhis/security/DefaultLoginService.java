package org.dhis.security;

import java.util.concurrent.TimeUnit;

import org.dhis.user.User;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;

public class DefaultLoginService
    implements LoginService
{
	public static final Integer MAX_ATTEMPTS = 5;
	public static final Integer EXPIRE_TIME = 60;
	
    /**
     * Cache for login attempts where usernames are keys and login attempts are values.
     */
    private final LoadingCache<String, Integer> USERNAME_LOGIN_ATTEMPTS_CACHE = Caffeine.newBuilder().expireAfterWrite(EXPIRE_TIME, TimeUnit.MINUTES).build(key -> 0);
	
	public LoadingCache<String, Integer> getUSERNAME_LOGIN_ATTEMPTS_CACHE() {
		return USERNAME_LOGIN_ATTEMPTS_CACHE;
	}

	@Override
    public void registerAuthenticationFailure( AuthenticationEvent event )
    {
    	USERNAME_LOGIN_ATTEMPTS_CACHE.put(event.getUsername(), USERNAME_LOGIN_ATTEMPTS_CACHE.get(event.getUsername()) + 1);
    }

    @Override
    public void registerAuthenticationSuccess( AuthenticationEvent event )
    {
    	USERNAME_LOGIN_ATTEMPTS_CACHE.invalidate(event.getUsername());
    }

    @Override
    public boolean isBlocked( User user )
    {
        return USERNAME_LOGIN_ATTEMPTS_CACHE.get(user.getUsername()) >= MAX_ATTEMPTS ? true : false;
    }
}
