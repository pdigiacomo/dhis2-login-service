package org.dhis.security;

import java.util.concurrent.TimeUnit;

import org.dhis.user.User;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;

/**
 * Implementation of the LoginService interface that registers authentication
 * events. <br />
 * The DefaultLoginService uses a Caffeine cache instance in order to register
 * authentication events and manage account lockouts. The cache keys are account
 * usernames. Each username in the cache corresponds to the number of login
 * attempts hit by the username's account owner at any given moment. Failed
 * login attempts increment this number, while a successful login attempt resets
 * this number to zero. This implementation is set with a limit of 5 login
 * attempts. Once this limit is reached, other attempts are blocked until the
 * attempt number is reset in the cache. <br />
 * Each cache entry has an expiration time of 60 minutes; every new write to an
 * entry refreshes the countdown to its fullest.
 * 
 * @author Pierluigi Di Giacomo
 *
 */
public class DefaultLoginService
    implements LoginService
{
	/**
	 * Constant specifying the number of failed login attempts allowed for this
	 * implementation.
	 */
	public static final Integer MAX_ATTEMPTS = 5;
	
	/**
	 * Constant specifying the period of time in minutes within which each entry
	 * is retained for this implementation.
	 */
	public static final Integer EXPIRE_TIME = 60;
	
	/**
	 * Cache for login attempts where usernames are keys and login attempts are
	 * values. This LoadingCache is built with a CacheLoader that sets values to
	 * zero when populating entries that are not found in the cache.
	 */
    private final LoadingCache<String, Integer> USERNAME_LOGIN_ATTEMPTS_CACHE = Caffeine.newBuilder().expireAfterWrite(EXPIRE_TIME, TimeUnit.MINUTES).build(key -> 0);
	
    /**
     * Getter method for the cache used internally.
     * @return the cache as a LoadingCache object
     */
	public LoadingCache<String, Integer> getUSERNAME_LOGIN_ATTEMPTS_CACHE() {
		return USERNAME_LOGIN_ATTEMPTS_CACHE;
	}

	/**
	 * Registers an authentication failure event. The value is fetched from the
	 * cache, incremented and written.
	 * 
	 * @param event
	 *            The AuthenticationEvent that triggers the call. The event's
	 *            username is taken as the key to operate on the cache.
	 */
	@Override
    public void registerAuthenticationFailure( AuthenticationEvent event )
    {
    	USERNAME_LOGIN_ATTEMPTS_CACHE.put(event.getUsername(), USERNAME_LOGIN_ATTEMPTS_CACHE.get(event.getUsername()) + 1);
    }

	/**
	 * Registers an authentication success event. The event is handled by
	 * resetting the cache entry corresponding to the event's username that
	 * caused the event.
	 * 
	 * @param event
	 *            The AuthenticationEvent that triggers the call. The event's
	 *            username is taken as the key to operate on the cache.
	 */
    @Override
    public void registerAuthenticationSuccess( AuthenticationEvent event )
    {
    	USERNAME_LOGIN_ATTEMPTS_CACHE.invalidate(event.getUsername());
    }

	/**
	 * Checks if the account owner is blocked for having reached the maximum
	 * number of login attempts. The check is performed by comparing the
	 * MAX_ATTEMPTS constant and the current number of attempts reached by this
	 * User. If this number equals or exceeds the constant, further logins are
	 * no longer allowed as long as the User's entry is retained in the cache.
	 * 
	 * @param user
	 *            The account owner whose username is taken as the key to access
	 *            to the cache.
	 * @return false if the User is blocked, true otherwise.
	 */
    @Override
    public boolean isBlocked( User user )
    {
        return USERNAME_LOGIN_ATTEMPTS_CACHE.get(user.getUsername()) >= MAX_ATTEMPTS ? false : true;
    }
}
