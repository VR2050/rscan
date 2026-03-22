package com.jbzd.media.movecartoons.bean.request;

import android.os.Build;
import com.alibaba.fastjson.JSON;
import java.util.HashMap;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class RequestSystemInfoBody {
    public String ad_method;
    public String app_code;
    public String captcha_key;
    public String captcha_value;
    public String channel_code;
    public String clipboard_text;
    public String device_id;
    public String device_info;
    public String domain;

    public RequestSystemInfoBody(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8) {
        this.captcha_key = str;
        this.captcha_value = str2;
        this.device_id = str3;
        this.clipboard_text = str4;
        this.app_code = str5;
        this.channel_code = str6;
        this.domain = str7;
        this.ad_method = str8;
    }

    public static String getDeviceInfoData() {
        HashMap hashMap = new HashMap();
        StringBuilder m586H = C1499a.m586H("");
        m586H.append(Build.VERSION.SDK_INT);
        hashMap.put("version.sdkInt", m586H.toString());
        hashMap.put("version.release", "" + Build.VERSION.RELEASE);
        hashMap.put("version.codename", "" + Build.VERSION.CODENAME);
        hashMap.put("board", "" + Build.BOARD);
        hashMap.put("bootloader", "" + Build.BOOTLOADER);
        hashMap.put("brand", "" + Build.BRAND);
        hashMap.put("device", "" + Build.DEVICE);
        hashMap.put("display", "" + Build.DISPLAY);
        hashMap.put("isPhysicalDevice", "" + (isEmulator() ^ true));
        hashMap.put("id", "" + Build.ID);
        hashMap.put("hardware", "" + Build.HARDWARE);
        hashMap.put("product", "" + Build.PRODUCT);
        hashMap.put("model", "" + Build.MODEL);
        hashMap.put("manufacturer", "" + Build.MANUFACTURER);
        hashMap.put("host", "" + Build.HOST);
        return JSON.toJSONString(hashMap);
    }

    public static boolean isEmulator() {
        if (!Build.BRAND.startsWith("generic") || !Build.DEVICE.startsWith("generic")) {
            String str = Build.FINGERPRINT;
            if (!str.startsWith("generic") && !str.startsWith("unknown")) {
                String str2 = Build.HARDWARE;
                if (!str2.contains("goldfish") && !str2.contains("ranchu")) {
                    String str3 = Build.MODEL;
                    if (!str3.contains("google_sdk") && !str3.contains("Emulator") && !str3.contains("Android SDK built for x86") && !Build.MANUFACTURER.contains("Genymotion")) {
                        String str4 = Build.PRODUCT;
                        if (!str4.contains("sdk_google") && !str4.contains("google_sdk") && !str4.contains("sdk") && !str4.contains("sdk_x86") && !str4.contains("vbox86p") && !str4.contains("emulator") && !str4.contains("simulator")) {
                            return false;
                        }
                    }
                }
            }
        }
        return true;
    }

    public String getApp_code() {
        return this.app_code;
    }

    public String getChannel_code() {
        return this.channel_code;
    }

    public String getClipboard_text() {
        return this.clipboard_text;
    }

    public String getDevice_id() {
        return this.device_id;
    }

    public String getDevice_info() {
        return getDeviceInfoData();
    }

    public String getDomain() {
        return this.domain;
    }

    public void setApp_code(String str) {
        this.app_code = str;
    }

    public void setChannel_code(String str) {
        this.channel_code = str;
    }

    public void setClipboard_text(String str) {
        this.clipboard_text = str;
    }

    public void setDevice_id(String str) {
        this.device_id = str;
    }

    public void setDevice_info(String str) {
        this.device_info = str;
    }

    public void setDomain(String str) {
        this.domain = str;
    }

    public RequestSystemInfoBody(String str, String str2, String str3, String str4, String str5, String str6) {
        this.device_id = str;
        this.clipboard_text = str2;
        this.app_code = str3;
        this.channel_code = str4;
        this.domain = str5;
        this.ad_method = str6;
    }

    public RequestSystemInfoBody(String str, String str2, String str3, String str4) {
        this.device_id = str;
        this.clipboard_text = str2;
        this.domain = str3;
        this.ad_method = str4;
    }
}
