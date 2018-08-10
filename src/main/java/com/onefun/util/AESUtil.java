package com.onefun.util;


import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import com.alibaba.fastjson.JSON;

public class AESUtil {
	private static final Logger logger = Logger.getLogger(AESUtil.class);  
    private static final String defaultCharset = "UTF-8";  
    private static final String KEY_AES = "AES";  
    private static final String KEY = "McjoeCheckOneTwoOne";
  /** 
   * 加密 
   * 
   * @param data 需要加密的内容 
   * @param key 加密密码 
   * @return 
   */  
  public static String encrypt(String data) {  
      return doAES(data, KEY, Cipher.ENCRYPT_MODE);  
  }  

  /** 
   * 解密 
   * 
   * @param data 待解密内容 
   * @param key 解密密钥 
   * @return 
   */  
  public static String decrypt(String data) {  
      return doAES(data, KEY, Cipher.DECRYPT_MODE);  
  }  

  /** 
   * 加解密 
   * 
   * @param data 待处理数据 
   * @param password  密钥 
   * @param mode 加解密mode 
   * @return 
   */  
  private static String doAES(String data, String key, int mode) {  
      try {  
          if (StringUtils.isBlank(data) || StringUtils.isBlank(key)) {  
              return null;  
          }  
          //判断是加密还是解密  
          boolean encrypt = mode == Cipher.ENCRYPT_MODE;  
          byte[] content;  
          //true 加密内容 false 解密内容  
          if (encrypt) {  
              content = data.getBytes(defaultCharset);  
          } else {  
              content = parseHexStr2Byte(data);  
          }  
          //1.构造密钥生成器，指定为AES算法,不区分大小写  
          KeyGenerator kgen = KeyGenerator.getInstance(KEY_AES);  
          //2.根据ecnodeRules规则初始化密钥生成器  
          //生成一个128位的随机源,根据传入的字节数组  
          kgen.init(128, new SecureRandom(key.getBytes()));  
          //3.产生原始对称密钥  
          SecretKey secretKey = kgen.generateKey();  
          //4.获得原始对称密钥的字节数组  
          byte[] enCodeFormat = secretKey.getEncoded();  
          //5.根据字节数组生成AES密钥  
          SecretKeySpec keySpec = new SecretKeySpec(enCodeFormat, KEY_AES);  
          //6.根据指定算法AES自成密码器  
          Cipher cipher = Cipher.getInstance(KEY_AES);// 创建密码器  
          //7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密解密(Decrypt_mode)操作，第二个参数为使用的KEY  
          cipher.init(mode, keySpec);// 初始化  
          byte[] result = cipher.doFinal(content);  
          if (encrypt) {  
              //将二进制转换成16进制  
              return parseByte2HexStr(result);  
          } else {  
              return new String(result, defaultCharset);  
          }  
      } catch (Exception e) {  
          logger.error("AES 密文处理异常", e);  
      }  
      return null;  
  }  
  /** 
   * 将二进制转换成16进制 
   * 
   * @param buf 
   * @return 
   */  
  public static String parseByte2HexStr(byte buf[]) {  
      StringBuilder sb = new StringBuilder();  
      for (int i = 0; i < buf.length; i++) {  
          String hex = Integer.toHexString(buf[i] & 0xFF);  
          if (hex.length() == 1) {  
              hex = '0' + hex;  
          }  
          sb.append(hex.toUpperCase());  
      }  
      return sb.toString();  
  }  
  /** 
   * 将16进制转换为二进制 
   * 
   * @param hexStr 
   * @return 
   */  
  public static byte[] parseHexStr2Byte(String hexStr) {  
      if (hexStr.length() < 1) {  
          return null;  
      }  
      byte[] result = new byte[hexStr.length() / 2];  
      for (int i = 0; i < hexStr.length() / 2; i++) {  
          int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);  
          int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);  
          result[i] = (byte) (high * 16 + low);  
      }  
      return result;  
  }
  
  
  
  
  //检查token
  public static Map<String,Object> tokenCheck(String token) throws ParseException{
	  //boolean sta = false;
	  String decrypt = decrypt(token);
	  if(decrypt==null){
		  return null;
	  }
	  Map<String , Object> map = JSON.parseObject(decrypt);
	  SimpleDateFormat df = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy",java.util.Locale.ENGLISH);
	  Date date1 = df.parse((String) map.get("time"));
	  map.remove("time");
	  if(new Date().getTime()-date1.getTime()<30*60*1000 && map!=null){
		  return map;
	  }
	  return null;
  }
  
//第一次登录的时候产生token(根据时间，还有openId)
  public static String loginToken(String openId,String session_key) throws ParseException{
	  Map<String ,Object> map = new HashMap<String, Object>();
	  SimpleDateFormat df = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy",java.util.Locale.ENGLISH);
	  map.put("openId", openId);
	  map.put("time",df.format(new Date()));
	  map.put("session_key",session_key);
	  return encrypt(JSON.toJSONString(map,true));
  }
  
  //新的token
  public static  String newToken(Map<String , Object> map) throws ParseException{
	  SimpleDateFormat df = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy",java.util.Locale.ENGLISH);
	  map.put("time",df.format(new Date()));
	  return encrypt(JSON.toJSONString(map,true));
  }

  public static void main(String[] args) throws Exception {    
      String content = "{'openId':'123','time':'Wed May 30 10:30:44 CST 2018'}"; 
      System.out.println("加密前：" + content);    
      System.out.println("加密密钥和解密密钥：" + KEY);
      String encrypt = encrypt(content);    
      System.out.println("加密后：" + encrypt);    
      String decrypt = decrypt(encrypt);    
      System.out.println("解密后：" + decrypt); 
      SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      Date date =sdf1.parse("2018-05-29 12:31:01");
      Date date2 =sdf1.parse("2018-05-29 12:31:00");
      Date date3 = new Date();
      long diff =date.getTime()-date2.getTime();
      System.out.println("时间差："+diff);
      
      System.out.println(new Date());
      Map<String , Object> map  =new HashMap<String ,Object>();
      map.put("Date怎样？","asds就是");
      System.out.println("转成String类型的时候："+map);
      
      String token ="DC61507752B156D3CEF73906484E81255D6C5"
      		+ "90E8A54C25EDB449953C63A5746BB9F6FCBBB4A69C755444E54D4C9C0D8694000E9368F93D4793E86E16C69EAA5596D67EFE9E221"
      		+ "54221F2A8C03521AAF753331F763B297D2792DC3B92BE603EA"; 
      
      System.out.println("有前端穿过的token:"+decrypt("DC615444E54D4C9C0D8694000E9368F93D4793E86E16C69EAA5596D67EFE9E22154221F2A8C03521AAF753331F763B297D2792DC07752B156D3CEF73906484E81255D6C590E8A54C25EDB449953C63A5746BB9F6FCBBB4A69C7553B92BE603EA"));
      System.out.println("tokencheck："+tokenCheck(token));
  }    
}
