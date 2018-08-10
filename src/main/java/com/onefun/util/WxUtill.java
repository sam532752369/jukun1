package com.onefun.util;

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.codehaus.xfire.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.alibaba.fastjson.JSON;
@Component
public class WxUtill {
	/**
	 * 根据不同小程序更换appId等、在application.properties中修改
	 */
	//@Value("${wx.appid}"):springboot不允许给静态变量直接注入值。通过set方法进行
	private static String appid;
	
	private static String secret;
	
	
	@Value("${wx.appid}")
	public  void setAppid(String appid) {
		WxUtill.appid = appid;
	}
	
	@Value("${wx.secret}")
	public  void setSecret(String secret) {
		WxUtill.secret = secret;
	}

	/**
	 * 获取用户信息包含userInfo和openId
	 * 调用时确认：
	 *    根据不同小程序更换appId等、在application.properties中修改
	 * @param encryptedData1
	 * @param iv1
	 * @param code
	 * @return
	 * @throws Exception
	 */
	public static Map<String,Object> getLoginUserInfo(String encryptedData,String iv,String code) throws Exception {
		Map<String, String> sessionAndOpIdMap = new HashMap<String, String>();
		// 1.根据code获取session_Kry和openId
		sessionAndOpIdMap = get(code);
		String openId = (String) sessionAndOpIdMap.get("openId");
		String sessionKey = (String) sessionAndOpIdMap.get("session_key");
		String errcode = (String) sessionAndOpIdMap.get("errcode");
		// System.out.println("errcode"+errcode);
		if (errcode != null && !"".equals(errcode) && !"null".equals(errcode)) {
			throw new Exception("errcode:" + sessionAndOpIdMap.get("errcode") + "---errmsg:" + sessionAndOpIdMap.get("errmsg"));
			//resJson.setMsg("errcode:" + sessionAndOpIdMap.get("errcode") + "---errmsg:" + sessionAndOpIdMap.get("errmsg"));

		}
		// 2.获取用户详细信息
		Map<String, Object> userInfo = getUserInfo(encryptedData, sessionKey, iv);
		userInfo.put("openId", openId);

		return userInfo;
	}
	
	/**
	 * 可获取openid及session_key,其实这里openid不需要获取，encryptedData解密后包含openid
	 * @param js_code
	 * @return
	 * @throws Exception
	 */
    public static Map<String, String> get(String js_code) throws Exception {
        //官方接口，需要自己提供appid，secret和js_code
        String requestUrl = "https://api.weixin.qq.com/sns/jscode2session?appid="+appid+"&secret="+secret+"&js_code="+js_code+"&grant_type=authorization_code";

        RestTemplate restTemplate=new RestTemplate();
        String r = restTemplate.getForObject(requestUrl,String.class);
        Object parse = JSON.parse(r);
        Map<String,Object>result=(Map)parse;
        String errcode =result.get("errcode")+"";
        String errmsg=(String)result.get("errmsg");
        
        String openid = (String) result.get("openid");
        String session_key = (String) result.get("session_key");
        Map<String,String> map = new HashMap<String, String>();
        map.put("openId",openid);
        map.put("session_key", session_key);
        map.put("errcode",errcode);
        map.put("errmsg", errmsg);
        return map;
    }
    
    /**
     * 获取信息
     * @param encryptedData
     * @param sessionkey
     * @param iv
     * @return
     */
    public static Map<String,Object> getUserInfo(String encryptedData,String sessionkey,String iv){
    	byte[] ivByte = Base64.decode(iv);
    	//System.out.println("ivByte:"+ivByte);
        // 被加密的数据
        byte[] dataByte = Base64.decode(encryptedData);
        //System.out.println("dataByte:"+dataByte);
        // 加密秘钥
        byte[] keyByte = Base64.decode(sessionkey);
        // 偏移量
//        byte[] ivByte = Base64.decode(iv);
        
        //System.out.println("lllll");
        
        try {
               // 如果密钥不足16位，那么就补足.  这个if 中的内容很重要
            int base = 16;
            if (keyByte.length % base != 0) {
                int groups = keyByte.length / base + (keyByte.length % base != 0 ? 1 : 0);
                byte[] temp = new byte[groups * base];
                Arrays.fill(temp, (byte) 0);
                //System.arraycopy(keyByte, 0, temp, 0, keyByte.length);
                keyByte = temp;
            }
            // 初始化
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding","BC");
            SecretKeySpec spec = new SecretKeySpec(keyByte, "AES");
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
            parameters.init(new IvParameterSpec(ivByte));
            cipher.init(Cipher.DECRYPT_MODE, spec, parameters);// 初始化
            byte[] resultByte = cipher.doFinal(dataByte);
            if (null != resultByte && resultByte.length > 0) {
                String result = new String(resultByte, "UTF-8");
                Object parse = JSON.parse(result);
                return (Map<String, Object>)parse;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }
}
