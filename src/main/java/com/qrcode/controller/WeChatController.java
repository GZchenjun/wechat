package com.qrcode.controller;

import com.qrcode.util.SignUtil;
import com.qrcode.util.XmlUtil;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import net.sf.json.JSONObject;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

@Controller
@RequestMapping("/wechat")
public class WeChatController {

    //天翎公众号
//  private static String APPID = "wx1bd80cac72a7fd02";
//  private static String SECRET = "18c61187a08137e72e6a079c0c3dae32";

    //微信测试公众号
    private static String APPID = "wxfc1cf7a9054187c9";
    private static String SECRET = "37692aacee4616c435123b19cdc352ef";

    private static String GET_ACCRESS_TOKEN_URL = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential";//获取access_token接口地址
    private static String TICKET = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=";//获取二维码ticket
    private static String QRCODE_URL = "https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=";//获取二维码图片地址
    private static String CREATE_MENU ="https://api.weixin.qq.com/cgi-bin/menu/create?access_token=";//创建菜单接口
    private static String GET_CURRENT_SELFMENU_INFO ="https://api.weixin.qq.com/cgi-bin/get_current_selfmenu_info?access_token=";
    private static String SEND_URL = "https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token=";

    private static HashMap<String,String> scene_map = new HashMap<String,String>();

    /*
     * 获取微信公众号access_token
     */
    public JSONObject getAccessToken(){
        String response = null;
        String url = GET_ACCRESS_TOKEN_URL + "&appid=" + APPID + "&secret=" + SECRET;
        try {
            CloseableHttpClient httpclient = null;
            CloseableHttpResponse httpresponse = null;
            try {
                httpclient = HttpClients.createDefault();
                HttpGet httpGet = new HttpGet(url);

                httpresponse = httpclient.execute(httpGet);
                response = EntityUtils
                        .toString(httpresponse.getEntity());
                JSONObject jsonObject = JSONObject.fromObject(response.toString());
                return jsonObject;
            } finally {
                if (httpclient != null) {
                    httpclient.close();
                }
                if (httpresponse != null) {
                    httpresponse.close();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /*
     * 根据access_token获取带参数二维码地址
     */
    public String getQRCode(String scene_id) {
        String access_token = getAccessToken().getString("access_token");
        String url = TICKET + access_token;
        String jsonMsg = "{\"expire_seconds\": \"86400\", \"action_name\": \"QR_SCENE\", \"action_info\": {\"scene\": {\"scene_id\": " + scene_id + "}}}";

        HttpClient httpClient = new HttpClient();
        httpClient.getHttpConnectionManager().getParams().setConnectionTimeout(15000);
        // 创建post请求方法实例对象
        PostMethod postMethod = new PostMethod(url);
        // 设置post请求超时时间
        postMethod.getParams().setParameter(HttpMethodParams.SO_TIMEOUT, 60000);
        postMethod.addRequestHeader("Content-Type", "application/json");
        try {
            //json格式的参数解析
            RequestEntity entity = new StringRequestEntity(jsonMsg, "Content-Type", "UTF-8");
            postMethod.setRequestEntity(entity);
            httpClient.executeMethod(postMethod);
            String result = postMethod.getResponseBodyAsString();
            postMethod.releaseConnection();
            JSONObject jsonObject = JSONObject.fromObject(result);
            String ticket = jsonObject.getString("ticket");
            String qrcodeurl = QRCODE_URL + ticket;
            return qrcodeurl;
        } catch (Exception e) {
            e.printStackTrace();
            return e.toString();
        }
    }

    @RequestMapping(value="/test",method=RequestMethod.GET)
    @ApiImplicitParams(
            {@ApiImplicitParam(name = "sceneId", value = "场景id", required = true, paramType = "query", dataType = "String"),
    })
    @ResponseBody
    public String test(String sceneId){
    	WeChatController wechatService = new WeChatController();
    	String qrcode = wechatService.getQRCode(sceneId);
        return qrcode;
    }

    @RequestMapping(value="/qrcode",method=RequestMethod.GET)
    public String test2(){
        return "/html/index.html";
    }

    /*@Autowired
    private JdbcTemplate jdbcTemplate;*/

    @RequestMapping(value="/getSceneId",method=RequestMethod.GET)
    @ApiImplicitParams(
            {@ApiImplicitParam(name = "sceneId", value = "场景id", required = true, paramType = "query", dataType = "String"),
            })
    @ResponseBody
    public int getSceneId(String sceneId) {
        int isSceneId = 0;
        String result = scene_map.get(sceneId);
        if(result != null && !result.isEmpty()){
            isSceneId = 1;
        }
        return isSceneId;
    }

    @RequestMapping(value="/removeSceneId",method=RequestMethod.GET)
    @ApiImplicitParams(
            {@ApiImplicitParam(name = "sceneId", value = "场景id", required = true, paramType = "query", dataType = "String"),
            })
    @ResponseBody
    public void removeSceneId(String sceneId) {
        //清除指定场景id
        scene_map.remove(sceneId);

        //检查已过期场景id并清除
        Date date = new Date();
        long timestamp = date.getTime();
        Iterator it = scene_map.entrySet().iterator();
        while(it.hasNext()){
            it=scene_map.keySet().iterator();
            String key = (String)it.next();
            long timestamp2 = Long.parseLong(scene_map.get(key));
            if(timestamp>(timestamp2+(5*60*1000))){
                scene_map.remove(key);
            }
        }
    }

    /*
     * 发送消息
     */
    public String sendMessage(String OPENID) {
        String access_token = getAccessToken().getString("access_token");
        System.out.println("access_token--->"+access_token);
        String url = SEND_URL + access_token;

        String jsonMsg = "{\n" +
                " \"touser\":\""+OPENID+"\","+
                " \"msgtype\":\"text\",\n" +
                " \"text\":\n" +
                "{\n" + " \"content\":\"感谢您的关注，天翎MyApps平台欢迎您~ \n" + "\n" + "License申请入口：\n" + "http://www.teemlink.com/experience/\n" + "服务热线：400-678-0211\n" + "技术Q群：182378297\n" + "微信商务客服：18922119255\"\n" +
                "}\n" + "}";

        HttpClient httpClient = new HttpClient();
        httpClient.getHttpConnectionManager().getParams().setConnectionTimeout(15000);
        // 创建post请求方法实例对象
        PostMethod postMethod = new PostMethod(url);
        // 设置post请求超时时间
        postMethod.getParams().setParameter(HttpMethodParams.SO_TIMEOUT, 60000);
        postMethod.addRequestHeader("Content-Type", "application/json");
        try {
            //json格式的参数解析
            System.out.println("jsonMsg-->"+jsonMsg);
            RequestEntity entity = new StringRequestEntity(jsonMsg, "Content-Type", "UTF-8");
            postMethod.setRequestEntity(entity);
            httpClient.executeMethod(postMethod);
            String result = postMethod.getResponseBodyAsString();
            postMethod.releaseConnection();
            JSONObject jsonObject = JSONObject.fromObject(result);
            String errmsg = jsonObject.getString("errmsg");
            return errmsg;

        } catch (Exception e) {
            e.printStackTrace();
            return e.toString();
        }
    }

    @RequestMapping(value = "/wx/reply.do")
    public void get2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String method = request.getMethod();
        if("GET".equals(method)) {
            String signature = request.getParameter("signature");/// 微信加密签名
            String timestamp = request.getParameter("timestamp");/// 时间戳
            String nonce = request.getParameter("nonce"); /// 随机数
            String echostr = request.getParameter("echostr"); // 随机字符串
            PrintWriter out = response.getWriter();

            if (SignUtil.checkSignature(signature, timestamp, nonce)) {
                out.print(echostr);
            }
            out.close();
        }else if("POST".equals(method)){

            // 解析xml数据，将解析结果存储在HashMap中
            Map<String, String> map = new HashMap<>();
            // 读取输入流
            SAXReader reader = new SAXReader();
            Document document = reader.read(request.getInputStream());
            // 得到xml根元素
            Element root = document.getRootElement();
            XmlUtil.parserXml(root, map);

            String MsgType = map.get("MsgType");//推送事件类型
            String Event = map.get("Event");//是否已关注
            String FromUserName = map.get("FromUserName");//关注者的openId
            for(Map.Entry<String, String> vo : map.entrySet()){
                vo.getKey();
                vo.getValue();
                System.out.println(vo.getKey()+"  "+vo.getValue());

            }


            if ("event".equals(MsgType) && ("subscribe".equals(Event) || "SCAN".equals(Event))) {
                System.out.println("---进入-->"+sendMessage(FromUserName));
                String EventKey = map.get("EventKey");//二维码对应的场景id
                if (EventKey.indexOf("qrscene_") > -1) {
                    EventKey = EventKey.substring(8);//第一次关注时会拼接了qrscene_，需要截取掉
                }
                Date date = new Date();
                String timestamp = String.valueOf(date.getTime());
                scene_map.put(EventKey,timestamp);
            }
        }
    }


    /*
     * 创建菜单
     */
    @RequestMapping(value = "/andCreateMenu")
    public String andCreateMenu(String MenuJsonList) {
        String access_token = getAccessToken().getString("access_token");
        String url = CREATE_MENU + access_token;
        HttpClient httpClient = new HttpClient();
        httpClient.getHttpConnectionManager().getParams().setConnectionTimeout(15000);
        // 创建post请求方法实例对象
        PostMethod postMethod = new PostMethod(url);
        // 设置post请求超时时间
        postMethod.getParams().setParameter(HttpMethodParams.SO_TIMEOUT, 60000);
        postMethod.addRequestHeader("Content-Type", "application/json");
        //postMethod.getParams().setParameter(HttpMethodParams.HTTP_CONTENT_CHARSET,"utf-8");
        try {
            //json格式的参数解析
            RequestEntity entity = new StringRequestEntity(MenuJsonList, "Content-Type", "UTF-8");
            postMethod.setRequestEntity(entity);
            httpClient.executeMethod(postMethod);
            System.out.println(postMethod.getResponseCharSet());
            String result = postMethod.getResponseBodyAsString();
            postMethod.releaseConnection();
            JSONObject jsonObject = JSONObject.fromObject(result);
            String errmsg = jsonObject.getString("errmsg");
            System.out.println("errcode-->"+errmsg);
            System.out.println("errcode11-->"+jsonObject.getString("errcode"));
            return  errmsg;
        } catch (Exception e) {
            e.printStackTrace();
            return e.toString();
        }

    }

    /**
     * 查询企业公众号配置的菜单
     * */
    @ResponseBody
    @RequestMapping(value = "/getCreateMenu")
    public String getCreateMenu() {
        String access_token = getAccessToken().getString("access_token");
        String url = GET_CURRENT_SELFMENU_INFO + access_token;
        System.out.println("access_token-->"+access_token);
        HttpClient httpClient = new HttpClient();
        httpClient.getHttpConnectionManager().getParams().setConnectionTimeout(15000);
        // 创建post请求方法实例对象

        GetMethod getMethod = new GetMethod(url);
        // 设置post请求超时时间
        getMethod.getParams().setParameter(HttpMethodParams.SO_TIMEOUT, 60000);
        getMethod.addRequestHeader("Content-Type", "application/json");
        try {
            //json格式的参数解析
            httpClient.executeMethod(getMethod);
            String result = getMethod.getResponseBodyAsString();
            getMethod.releaseConnection();
            JSONObject jsonObject = JSONObject.fromObject(result);
            String selfmenu_info ="{\n" +
                    "     \"button\":[\n" +
                    "      {\n" +
                    "           \"name\":\"产品方案\",\n" +
                    "           \"sub_button\":[\n" +
                    "           {\t\n" +
                    "               \"type\":\"view\",\n" +
                    "               \"name\":\"在线试用\",\n" +
                    "               \"url\":\"http://office.teemlink.com:60181/signon\"\n" +
                    "            },\n" +
                    "            {\n" +
                    "                 \"type\":\"view\",\n" +
                    "                 \"name\":\"解决方案\",\n" +
                    "                 \"url\":\"http://www.teemlink.com/case/\"\n" +
                    "             },\n" +
                    "            {\n" +
                    "                 \"type\":\"view\",\n" +
                    "                 \"name\":\"天翎BPM\",\n" +
                    "                 \"url\":\"http://www.teemlink.com/bpm/\"\n" +
                    "             }, {\n" +
                    "                 \"type\":\"view\",\n" +
                    "                 \"name\":\"MyApps平台\",\n" +
                    "                 \"url\":\"http://www.teemlink.com/myapps/\"\n" +
                    "             }]\n" +
                    "       },{\n" +
                    "           \"name\":\"应用实践\",\n" +
                    "           \"sub_button\":[\n" +
                    "           {\n" +
                    "           \"type\": \"view\", \n" +
                    "           \"name\": \"免费License\", \n" +
                    "           \"url\": \"https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Service_Center_messages.html#7\"\n" +
                    "          },\n" +
                    "            {\n" +
                    "                 \"type\":\"view\",\n" +
                    "                 \"name\":\"技术支持\",\n" +
                    "                 \"url\":\"http://www.teemlink.com/case/\"\n" +
                    "             },\n" +
                    "            {\n" +
                    "                 \"type\":\"view\",\n" +
                    "                 \"name\":\"天翎BPM\",\n" +
                    "                 \"url\":\"http://www.teemlink.com/bpm/\"\n" +
                    "             }, {\n" +
                    "                 \"type\":\"view\",\n" +
                    "                 \"name\":\"MyApps平台\",\n" +
                    "                 \"url\":\"http://www.teemlink.com/myapps/\"\n" +
                    "             }]\n" +
                    "       },{\n" +
                    "           \"name\":\"互动交流\",\n" +
                    "           \"sub_button\":[\n" +
                    "           {\n" +
                    "           \"type\": \"view\", \n" +
                    "           \"name\": \"免费License\", \n" +
                    "           \"url\": \"https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Service_Center_messages.html#7\"\n" +
                    "          },\n" +
                    "            {\n" +
                    "                 \"type\":\"view\",\n" +
                    "                 \"name\":\"技术支持\",\n" +
                    "                 \"url\":\"http://www.teemlink.com/case/\"\n" +
                    "             },\n" +
                    "            {\n" +
                    "                 \"type\":\"view\",\n" +
                    "                 \"name\":\"天翎BPM\",\n" +
                    "                 \"url\":\"http://www.teemlink.com/bpm/\"\n" +
                    "             }, {\n" +
                    "                 \"type\":\"view\",\n" +
                    "                 \"name\":\"MyApps平台\",\n" +
                    "                 \"url\":\"http://www.teemlink.com/myapps/\"\n" +
                    "             }]\n" +
                    "       }]\n" +
                    " }";
            if(jsonObject!=null){
                System.out.println("jsonObject-->"+jsonObject.toString());
                System.out.println("添加菜单接口---》"+andCreateMenu(selfmenu_info));
                return  jsonObject.toString();
            }

            return  "";

        } catch (Exception e) {
            e.printStackTrace();
            return e.toString();
        }

    }





    @RequestMapping(value = "/wx.do")
    public void get1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Enumeration pNames = request.getParameterNames();

        while (pNames.hasMoreElements()) {
            String name = (String) pNames.nextElement();
            String value = request.getParameter(name);
            System.out.print(name + "=" + value);

            String log = "name =" + name + "     value =" + value;

        }

        String signature = request.getParameter("signature");/// 微信加密签名
        String timestamp = request.getParameter("timestamp");/// 时间戳
        String nonce = request.getParameter("nonce"); /// 随机数
        String echostr = request.getParameter("echostr"); // 随机字符串
        PrintWriter out = response.getWriter();

        if (SignUtil.checkSignature(signature, timestamp, nonce)) {
            out.print(echostr);
        }
        System.out.println(request.getMethod());

        // 解析xml数据，将解析结果存储在HashMap中
        Map<String, String> map = new HashMap<>();
        // 读取输入流
        SAXReader reader = new SAXReader();
        Document document = reader.read(request.getInputStream());
        // 得到xml根元素
        Element root = document.getRootElement();
        XmlUtil.parserXml(root, map);

        String MsgType = map.get("MsgType");//推送事件类型
        String Event = map.get("Event");//是否已关注
        for(Map.Entry<String, String> vo : map.entrySet()){
            vo.getKey();
            vo.getValue();
            System.out.println(vo.getKey()+"  "+vo.getValue());

        }
        String FromUserName = map.get("FromUserName");

        if ("event".equals(MsgType) && ("subscribe".equals(Event) || "SCAN".equals(Event))) {
            String EventKey = map.get("EventKey");//二维码对应的场景id
            System.out.println("---进入-->"+sendMessage(FromUserName));
            if (EventKey.indexOf("qrscene_") > -1) {
                EventKey = EventKey.substring(8);//第一次关注时会拼接了qrscene_，需要截取掉
            }
            Date date = new Date();
            String timestamps = String.valueOf(date.getTime());
            scene_map.put(EventKey,timestamps);
        }

        out.close();
        out = null;

    }


    private static String token = "teemlink";

    /**
     * 校验签名
     */
    public static boolean checkSignature(String signature, String timestamp, String nonce) {
        System.out.println("signature:" + signature + "timestamp:" + timestamp + "nonc:" + nonce);
        String[] arr = new String[] { token, timestamp, nonce };
        // 将token、timestamp、nonce三个参数进行字典序排序
        Arrays.sort(arr);
        StringBuilder content = new StringBuilder();
        for (int i = 0; i < arr.length; i++) {
            content.append(arr[i]);
        }
        MessageDigest md = null;
        String tmpStr = null;

        try {
            md = MessageDigest.getInstance("SHA-1");
            // 将三个参数字符串拼接成一个字符串进行sha1加密
            byte[] digest = md.digest(content.toString().getBytes());
            tmpStr = byteToStr(digest);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        content = null;
        // 将sha1加密后的字符串可与signature对比，标识该请求来源于微信
        System.out.println(tmpStr.equals(signature.toUpperCase()));
        return tmpStr != null ? tmpStr.equals(signature.toUpperCase()) : false;
    }



    /**
     * 将字节数组转换为十六进制字符串
     *
     * @param byteArray
     * @return
     */
    private static String byteToStr(byte[] byteArray) {
        String strDigest = "";
        for (int i = 0; i < byteArray.length; i++) {
            strDigest += byteToHexStr(byteArray[i]);
        }
        return strDigest;
    }

    /**
     * 将字节转换为十六进制字符串
     *
     * @param mByte
     * @return
     */
    private static String byteToHexStr(byte mByte) {
        char[] Digit = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        char[] tempArr = new char[2];
        tempArr[0] = Digit[(mByte >>> 4) & 0X0F];
        tempArr[1] = Digit[mByte & 0X0F];

        String s = new String(tempArr);
        return s;
    }

}

