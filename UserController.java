package com.wmk.ex.controller;

import java.io.File;
import java.io.IOException;
import java.util.Iterator;
import java.util.UUID;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.wmk.ex.security.CustomUserDetailService;
import com.wmk.ex.service.UserService;
import com.wmk.ex.vo.CustomUser;
import com.wmk.ex.vo.KakaoProfile;
import com.wmk.ex.vo.KakaoProfile.KakaoAccount;
import com.wmk.ex.vo.OAuthToken;
import com.wmk.ex.vo.ResponseVO;
import com.wmk.ex.vo.UserVO;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j;

@Log4j
@Controller
@AllArgsConstructor
public class UserController {

	private UserService userService;

	@Inject
	private BCryptPasswordEncoder passEncoder;

	@Autowired
	private CustomUserDetailService customUserDetailService;

	@PostMapping("/addUser")
	public String adduser(UserVO userVO) {

		log.info("post register");
		userService.addUser(userVO);

		return "redirect:/loginForm";
	}

	// delete view ������
	@GetMapping("/userDeleteView")
	public String userDeleteView() {
		log.info("welcome userDeleteView!");
		return "user/UserDeleteView";
	}

	// 회원탈퇴
	@PostMapping("user/userDelete")
	@ResponseBody
	public String userDelete(@RequestBody UserVO userVO, Authentication authentication, HttpServletRequest request)
			throws Exception {
		Gson gson = new Gson();
		CustomUser loginInfo = (CustomUser) authentication.getPrincipal();
		log.info("loginInfo:  " + loginInfo);
		boolean isValidPassword = passEncoder.matches(userVO.getPw(), loginInfo.getUser().getPw());
		
		log.info("userVO.getPw()   :  " + userVO.getPw());
		log.info("loginInfo.getUser().getPw()   :  " +  loginInfo.getUser().getPw());
		log.info("true & fail isValidPassword   :  " + isValidPassword);
		log.info("login ID      :  " + loginInfo.getUser().getId());
		log.info("login password   :  " + userVO.getPw());
		log.info("login Encoding password   :  " + loginInfo.getUser().getPw());
		log.info(" true & fail   : " + isValidPassword + "  matches   :  " + userVO.getPw() + "     :     "
				+ loginInfo.getUser().getPw());
		
		if (isValidPassword) {
			userVO.setId(loginInfo.getUser().getId());
			userVO.setPw(loginInfo.getUser().getPw());

			userService.userDelete(userVO);
			log.info("Delete success");

			request.getSession().invalidate();
			log.info("logout success ");

			return gson.toJson(new ResponseVO<>(200, "success"));
		}
		log.info("notValidPassword");
		return gson.toJson(new ResponseVO<>(400, "fail"));

	}

	// 회원가입 아이디 중복체크
	@GetMapping(value = "/user/check")
	@ResponseBody
	public String checkSameId(@RequestParam("id") String id) {
		Gson gson = new Gson();
		log.info("Login ID  :  " + id);
		try {
			if (id.isEmpty()) {
				log.info("id.isEmpty :  " + id.isEmpty());
				return gson.toJson(new ResponseVO<>(401, false));
			}

			UserVO userVO = userService.getUserById(id);
			log.info("UserVO = null ? notnull? : " + userVO);
			if (userVO != null) {
				return gson.toJson(new ResponseVO<>(400, false));
			}

		} catch (Exception e) {
			return gson.toJson(new ResponseVO<>(500, false));
		}
		return gson.toJson(new ResponseVO<>(200, true));

	}

	
	@GetMapping("/auth/kakao/callback")
	public String kakaoCallback(String code, HttpServletRequest request) throws Exception {

		Gson gson = new Gson();
		RestTemplate rt = new RestTemplate();

		HttpHeaders headers = new HttpHeaders();
		headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "authorization_code");
		params.add("client_id", "af9546b83fbd65051801d2e327f8c259");
		params.add("redirect_uri", "http://localhost:8282/ex/auth/kakao/callback");
		params.add("code", code);

		HttpEntity<MultiValueMap<String, String>> kakaoTokenRequest = new HttpEntity<>(params, headers);

		ResponseEntity<String> response = rt.exchange("https://kauth.kakao.com/oauth/token", HttpMethod.POST,
				kakaoTokenRequest, String.class);

		ObjectMapper objectMapper = new ObjectMapper();
		OAuthToken oauthToken = null;
		try {
			oauthToken = objectMapper.readValue(response.getBody(), OAuthToken.class);
		} catch (JsonParseException e) {
			e.printStackTrace();
		} catch (JsonMappingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		RestTemplate rt2 = new RestTemplate();

		
		HttpHeaders headers2 = new HttpHeaders();
		headers2.add("Authorization", "Bearer " + oauthToken.getAccess_token());
		headers2.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");


		HttpEntity<MultiValueMap<String, String>> kakaoProfileRequest2 = new HttpEntity<>(headers2);


		ResponseEntity<String> response2 = rt2.exchange("https://kapi.kakao.com/v2/user/me", HttpMethod.POST,
				kakaoProfileRequest2, String.class);

		System.out.println(response2.getBody());

		ObjectMapper objectMapper2 = new ObjectMapper();
		KakaoProfile kakaoProfile = null;
		try {
			// 카카오 로그인 정보 받은 곳
			kakaoProfile = objectMapper2.readValue(response2.getBody(), KakaoProfile.class);
			log.info(gson.toJson(kakaoProfile));
		} catch (JsonParseException e) {
			e.printStackTrace();
		} catch (JsonMappingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// 카카오톡 고유 아이디값
		String socialUserId = kakaoProfile.getId().toString();
		UserVO loginUserInfo = userService.getUserByIdAndLoginType(socialUserId, "kakao");

		log.info("socialUserId    :"+socialUserId);
		log.info("loginUserInfo   :"+loginUserInfo);
		log.info("테스트");

		if (loginUserInfo == null) {
			// 여기 카카오 로그인 타입을 추가
			UserVO socialRegisterUser = UserVO.builder()
					.id(socialUserId)	//카카오에서 제공하는 아이디 
					.pw(kakaoProfile.getId() + "kakao")
					.nickname(kakaoProfile.getProperties()//카카오에 설정된 닉네임
					.getNickname())
					.email(" ")
					.nationality("nationality")
					.enabled(1)
					.login_Type("kakao")//로그인 타입에 kakao넣어줌 
					.build();
			log.info(" 정보를 넣어줌!! 	;" + gson.toJson(socialRegisterUser));
			userService.addUser(socialRegisterUser);
			//service통해서 유저 추가 
		}

		// 시큐리티 제공하는 유저 정보 조회 서비스를 통한 유저 정보 조회
		UserDetails userDetails = customUserDetailService.loadUserByUsername(socialUserId);

		log.info(" 로그인처리 직전 	;" + gson.toJson(loginUserInfo));
		// 여기서 로그인 처리

		// 유저정보 + 비밀번호(2번쨰 파라미터) 를 통한 로그인 권한정보 생성
		Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, socialUserId + "kakao",
				userDetails.getAuthorities());
		// 로그인 정보를 스프링 시큐리티 컨텍스트에 넣기 위해 컨텍스트 정보 가져오기
		SecurityContext securityContext = SecurityContextHolder.getContext();
		// 스프링 시큐리티 권한정보에 위에서 만든 권한정보를 넣어준다.
		securityContext.setAuthentication(authentication);
		HttpSession session = request.getSession(true);
		// 시큐리티 로그인 세션을 생성
		session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);

		return "redirect:/index"; // 여기서 홈으로 리다리엑트 하면 됨
	}

	@GetMapping("/userModify")
	public String modify() {
		log.info("modify personal information");
		return "user/userModify";
	}

	@GetMapping("/userPwModify")
	public String Pwmodify() {
		log.info("password modify personal information");
		return "user/userPwModify";
	}

	@PostMapping("/update")
	public String userModify(UserVO userVO, HttpSession session) {
		log.info("to Modify user information");

		log.info(userVO.getId());
		log.info(userVO.getPw());
		log.info(userVO.getNickname());
		log.info(userVO.getEmail());
		log.info(userVO.getNationality());

		userService.modifyUser(userVO);
		session.invalidate();

		return "redirect:/index";
	}

	@PostMapping("/pwupdate")
	public String userPwModify(UserVO userVO, HttpSession session) {
		log.info("to Modify user information");

		log.info(userVO.getId());
		log.info(userVO.getPw());

		userService.pwModifyUser(userVO);
		session.invalidate();

		return "redirect:/index";
	}
	
	@GetMapping("/uploadProfile")
	public String uploadProfile() {
		log.info("upload Profile Img");
		return "user/userUploadProfile";
	}

	@PostMapping("/uploadProfileImg")
	public String uploadProfileImg(UserVO userVO, Model model, MultipartHttpServletRequest mpRequest)  throws Exception {

		  Iterator<String> iterator = mpRequest.getFileNames();
		  
		  MultipartFile multipartFile; 
		  String originalFileName = null; 
		  String originalFileExtension; 
		  String storedFileName = null;
		  
		  String filePath = "C:\\WMKOREA\\ThumbnailImg\\"; // 이미지 저장경로
		  
		  File file = new File(filePath); 
		  if (file.exists() == false) { 
			  file.mkdirs();
		  }
		  
		  multipartFile = mpRequest.getFile(iterator.next()); 
		  if(multipartFile.isEmpty() == false) { 
		  originalFileName = multipartFile.getOriginalFilename(); 
		  originalFileExtension = originalFileName.substring(originalFileName.lastIndexOf(".")); 
		  storedFileName = getRandomString() + originalFileExtension;
		  
		  file = new File(filePath + storedFileName); 
		  multipartFile.transferTo(file);
		  
		  }
		  
		  Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal(); 
		  String userId = ((UserDetails)principal).getUsername(); 
		  userVO.setId(userId);
		  userVO.setProfile(originalFileName);
		  userVO.setImgName(storedFileName);
		  userService.uploadProfileImg(userVO);
		return "redirect:/mypage";
	}

	public static String getRandomString() {
		return UUID.randomUUID().toString().replaceAll("-", "");
	}

}