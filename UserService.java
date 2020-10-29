package com.wmk.ex.service;

import javax.inject.Inject;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.wmk.ex.mapper.UserMapper;
import com.wmk.ex.vo.UserVO;
import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j;

@Log4j
@NoArgsConstructor
@Service
public class UserService {

	@Inject
	private BCryptPasswordEncoder passEncoder;

	@Inject
	private UserMapper userMapper;

	public void addUser(UserVO userVO) {
		
		log.info("addUser");
		
		String pw = userVO.getPw();

		String encode = passEncoder.encode(pw);

		userVO.setPw(encode);

		// 로그인 타입이 없는건 소셜 로그인이 아닌 일반 로그인 처리
		if (null == userVO.getLogin_Type()) {
			userVO.setLogin_Type("NORMAL");
		}

		userMapper.insertUser(userVO);

		userMapper.insertAuthorities(userVO);

	}
	
	

	@Transactional
	public void userDelete(UserVO userVO) throws Exception {
		log.info("delete Start");
		String userId = userVO.getId();
		log.info("login ID   :   " + userVO.getId());
		log.info("login PW   :   " + userVO.getPw());
		userMapper.authori(userId);
		log.info("userVO   :"+userVO);
		userMapper.delMember(userVO);

		log.info("delete end");
	}

	public UserVO getUserById(String id) {
		if (id.isEmpty()) {
			log.info("userId is empty");
			return null;
		}

		return userMapper.readUser(id);
	}

	public UserVO getUserByIdAndLoginType(String id, String login_Type) {

		return userMapper.readUserByIdAndLoginType(id, login_Type);
	}

	public String getEncodePassword(String pw) {
		log.info("pw" + pw);
		return passEncoder.encode(pw);
	}

	public void modifyUser(UserVO userVO) {

		String pw = userVO.getPw();
		log.info(pw);
		String encode = passEncoder.encode(pw);

		userVO.setPw(encode);

		userMapper.modifyUser(userVO);
		;

		log.info(userVO);

	}
	
	public void pwModifyUser(UserVO userVO) {

		String pw = userVO.getPw();
		log.info(pw);
		String encode = passEncoder.encode(pw);

		userVO.setPw(encode);

		userMapper.pwModifyUser(userVO);
		;

		log.info(userVO);

	}

	public int getUser(String member_id) {
		return userMapper.idChk(member_id);
	}
	
	public void uploadProfileImg(UserVO userVO) {
		userMapper.uploadProfileImg(userVO);
	}
	
	public UserVO readUser(String id) {
		return userMapper.readUser(id);
	}
}