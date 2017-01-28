package com.example;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;

import net.minidev.json.JSONObject;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * nimbusds jwt 生成token及校验
 *
 * @author Jiantao.Yang
 *         2016/12/29 12:19
 * @version 1.0
 */

public class Jwt {
    /**
     * 秘钥
     */
    public static final String SECRET = "jiantaojiantaojiantaojiantaojiantaojiantaojiantao";

    /**
     * 根据payload、header加密生成token
    */
    public static String createToken( Payload payload, JWSHeader header) {
        if(payload == null || header == null){
            throw new NullPointerException("payload or header is null");
        }
        JWSObject jwsObject = new JWSObject(header, payload);
        try {
            JWSSigner signer = new MACSigner(SECRET.getBytes());
            jwsObject.sign(signer);
        } catch (JOSEException e) {
            System.err.println(" JOSEException :" + e.getMessage());
            e.printStackTrace();
        }
        return jwsObject.serialize();
    }

    public static boolean validToken(String token) {
        boolean validState = false;
        try {
            JWSObject jwsObject = JWSObject.parse(token);
            Payload payload = jwsObject.getPayload();
            JWSVerifier verifier = new MACVerifier(SECRET);
            if (jwsObject.verify(verifier)) {
                validState = true;
                JSONObject jsonOBj = payload.toJSONObject();
                System.out.println(" token is valid .. payload :"+jsonOBj);
                if (jsonOBj.containsKey("ext")) {
                    long extTime = Long.valueOf(jsonOBj.get("ext").toString());
                    long curTime = System.currentTimeMillis();
                    if (curTime > extTime) {
                        validState = false;
                        System.out.println(" token is invalid , because token has been expired .");
                    }
                }
            } else {
                System.out.println(" token is invalid .. payload :"+payload.getOrigin());
            }

        } catch (JOSEException e) {
            validState = false;
            System.out.println(" token is valid .. exception :"+e.getMessage());
        } catch (ParseException e) {
            validState = false;
            System.out.println(" token is valid .. exception :"+e.getMessage());
        }
        return validState;
    }


    public static void main(String[] args) {
        String token = Jwt.createToken(getPaylod(), getDefaultHeader());
        System.out.println("token = "+token);

        boolean result = Jwt.validToken(token);
        System.out.println("validToken ? result = "+result);
    }

    //默认的header。指定类型和加密算法
    private static JWSHeader getDefaultHeader() {
        return new JWSHeader(JWSAlgorithm.HS256, JOSEObjectType.JWT, null, null, null, null, null, null, null, null, null, null, null);
    }

    private static Payload getPaylod() {
        Charset gbk = Charset.forName("GBK");
        Map<String, Object> paramsMap = new HashMap<String, Object>();
        paramsMap.put("out_doctor_id", 57027641);
        paramsMap.put("doctor_name", new String("认证医生".getBytes(gbk), StandardCharsets.UTF_8));//这里进行了一次转码：输入gbk格式，输出utf-8
        paramsMap.put("title", 57027641);
        paramsMap.put("department", new String("华西大学".getBytes(gbk), StandardCharsets.UTF_8));
        paramsMap.put("mobile", new String("15824636549".getBytes(gbk), StandardCharsets.UTF_8));
        paramsMap.put("hospital", 57027641);

        Map<String, Object> payloadJson = new HashMap<String, Object>();
        payloadJson.put("app_id", "3174042");//用户id
        payloadJson.put("service", "http://web.qa.medlinker.com/h5/d2d/my.html?a=b");
        payloadJson.put("ext", System.currentTimeMillis()+1000*100);
        payloadJson.put("params", paramsMap);
        //支持json嵌套
        JSONObject jsonObject = new JSONObject(payloadJson);
        return new Payload(jsonObject);
    }
}
