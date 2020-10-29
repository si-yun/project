package com.wmk.ex.security;

import javax.inject.Inject;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.wmk.ex.vo.CustomUser;
import com.wmk.ex.vo.UserVO;
import com.wmk.ex.mapper.UserMapper;
import lombok.extern.log4j.Log4j;

@Log4j
@Service
public class CustomUserDetailService implements UserDetailsService {
	
	@Inject
	private UserMapper userMapper;
	
	@Override
	public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
		
		log.warn("Load User By User number: " + id);		
		UserVO userVo = userMapper.readUser(id);
		log.warn("queried by UserVO mapper: " + userVo);		
		
		return userVo == null ? null : new CustomUser(userVo);
	}
	
	
}

