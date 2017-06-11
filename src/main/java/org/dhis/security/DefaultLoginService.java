package org.dhis.security;

import java.util.concurrent.TimeUnit;

import org.dhis.user.User;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;

public class DefaultLoginService
    implements LoginService
{
	private static final Integer MAX_ATTEMPTS = 5;
	private static final Integer TIME_LIMIT_MINUTES = 60;
    /**
     * Cache for login attempts where usernames are keys and login attempts are values.
     */
    private final LoadingCache<String, Integer> USERNAME_LOGIN_ATTEMPTS_CACHE = Caffeine.newBuilder().expireAfterWrite(TIME_LIMIT_MINUTES, TimeUnit.MINUTES).build(key -> 0);
    
    // TODO Instantiate and configure this cache (https://github.com/ben-manes/caffeine)
    
    @Override
    public void registerAuthenticationFailure( AuthenticationEvent event )
    {
        // TODO Implement this method        
    	USERNAME_LOGIN_ATTEMPTS_CACHE.put(event.getUsername(), USERNAME_LOGIN_ATTEMPTS_CACHE.get(event.getUsername()) + 1);
    }

    @Override
    public void registerAuthenticationSuccess( AuthenticationEvent event )
    {
        // TODO Implement this method        
    	USERNAME_LOGIN_ATTEMPTS_CACHE.invalidate(event.getUsername());
    }

    @Override
    public boolean isBlocked( User user )
    {
        // TODO Implement this method        
        return USERNAME_LOGIN_ATTEMPTS_CACHE.get(user.getUsername()) >= MAX_ATTEMPTS ? true : false;
    }
}
