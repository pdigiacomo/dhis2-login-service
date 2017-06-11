package org.dhis.security;

import static org.junit.Assert.*;

import org.dhis.user.User;
import org.junit.Before;
import org.junit.Test;

import com.github.benmanes.caffeine.cache.LoadingCache;

public class LoginServiceTest
{
    private DefaultLoginService loginService;
    
    @Before
    public void before()
    {
        loginService = new DefaultLoginService();
    }
    
    @Test
    public void testRegisterAuthenticationSuccess_inCache() {
//    	Prepare
    	LoadingCache<String,Integer> cache = loginService.getUSERNAME_LOGIN_ATTEMPTS_CACHE();
    	cache.put("foo", DefaultLoginService.MAX_ATTEMPTS - 1);
    	AuthenticationEvent successfulEvent = new AuthenticationEvent("foo");
    	
//    	Execute
    	loginService.registerAuthenticationSuccess(successfulEvent);
    	
//    	Verify
    	Integer cacheAfterSuccess = cache.get("foo");
    	assertEquals(0, cacheAfterSuccess.intValue());
    }
    
    @Test
    public void testRegisterAuthenticationSuccess_notInCache() {
//    	Prepare
    	LoadingCache<String,Integer> cache = loginService.getUSERNAME_LOGIN_ATTEMPTS_CACHE();
    	cache.cleanUp();
    	assertEquals(0, cache.estimatedSize());
    	AuthenticationEvent successfulEvent = new AuthenticationEvent("foo");
    	
//    	Execute
    	loginService.registerAuthenticationSuccess(successfulEvent);
    	
//    	Verify
    	Integer cacheAfterSuccess = cache.get("foo");
    	assertEquals(0, cacheAfterSuccess.intValue());
    }
    
    @Test
    public void testRegisterAuthenticationFailure_inCache() {
//    	Prepare
    	LoadingCache<String,Integer> cache = loginService.getUSERNAME_LOGIN_ATTEMPTS_CACHE();
    	cache.put("foo", DefaultLoginService.MAX_ATTEMPTS - 1);
    	AuthenticationEvent failingEvent = new AuthenticationEvent("foo");
    	
//    	Execute
    	loginService.registerAuthenticationFailure(failingEvent);
    	
//    	Verify
    	Integer cacheAfterFailure = cache.get("foo");
    	assertEquals(DefaultLoginService.MAX_ATTEMPTS.intValue(), cacheAfterFailure.intValue());
    }

    @Test
    public void testRegisterAuthenticationFailure_notInCache() {
//    	Prepare
    	LoadingCache<String,Integer> cache = loginService.getUSERNAME_LOGIN_ATTEMPTS_CACHE();
    	cache.cleanUp();
    	assertEquals(0, cache.estimatedSize());
    	AuthenticationEvent failingEvent = new AuthenticationEvent("foo");
    	
//    	Execute
    	loginService.registerAuthenticationFailure(failingEvent);
    	
//    	Verify
    	Integer cacheAfterFailure = cache.get("foo");
    	assertEquals(1, cacheAfterFailure.intValue());
    }
    
    @Test
    public void testIsBlocked_inCache_underAttemptLimit() {
//    	Prepare
    	LoadingCache<String,Integer> cache = loginService.getUSERNAME_LOGIN_ATTEMPTS_CACHE();
    	cache.put("foo", DefaultLoginService.MAX_ATTEMPTS - 1);
    	User user = new User("foo");
    	
//    	Execute
    	boolean unblockedUser = loginService.isBlocked(user);
    	
//    	Verify
    	assertEquals(true, unblockedUser);
    }
    
    @Test
    public void testIsBlocked_inCache_equalsAttemptLimit() {
//    	Prepare
    	LoadingCache<String,Integer> cache = loginService.getUSERNAME_LOGIN_ATTEMPTS_CACHE();
    	cache.put("foo", DefaultLoginService.MAX_ATTEMPTS);
    	User user = new User("foo");
    	
//    	Execute
    	boolean blockedUser = loginService.isBlocked(user);
    	
//    	Verify
    	assertEquals(false, blockedUser);
    }
    
    @Test
    public void testIsBlocked_notInCache() {
//    	Prepare
    	LoadingCache<String,Integer> cache = loginService.getUSERNAME_LOGIN_ATTEMPTS_CACHE();
    	cache.cleanUp();
    	assertEquals(0, cache.estimatedSize());
    	User user = new User("foo");
    	
//    	Execute
    	boolean blockedUser = loginService.isBlocked(user);
    	
//    	Verify
    	assertEquals(true, blockedUser);
    }
}
