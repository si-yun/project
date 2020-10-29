package com.wmk.ex.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.wmk.ex.vo.UserVO;

@Mapper
public interface UserMapper {

	public int insertUser(UserVO userVO);
	public void insertAuthorities(UserVO userVO);
	
	//kakao social
	public UserVO readUser(String id);
	public UserVO readUserLoginType(String login_Type);
	public UserVO readUserByIdAndLoginType(@Param("id")String id,@Param("login_Type")String login_Type);
	
	//DeleteUsers
	public void authori(String id);
	public void delMember(UserVO userVO);
	
	//UpdateUsers
	public void modifyUser(UserVO userVO);
	public void pwModifyUser(UserVO userVO);

	//UserIdCheck
	public int idChk(String id);
	
	//UpdateUsers
	public void uploadProfileImg(UserVO userVO);
}
	
