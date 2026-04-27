package com.ding.rtc.http;

import android.text.TextUtils;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes.dex */
public class HttpStackResponse {
    public int code;
    public String headers;
    public long lastModified;
    public byte[] result = new byte[0];

    public String toString() {
        return "code:" + this.code + ", headers: " + this.headers + ", res:" + getResultString();
    }

    public int getCode() {
        return this.code;
    }

    public long getLastModified() {
        return this.lastModified;
    }

    public byte[] getResult() {
        return this.result;
    }

    public String getResultString() {
        return byte2String(this.result);
    }

    public String getHeaderFields() {
        return this.headers;
    }

    public HashMap<String, String> getHeaderMap() {
        HashMap<String, String> map = new HashMap<>();
        if (TextUtils.isEmpty(this.headers)) {
            return map;
        }
        try {
            JSONObject jsonObject = new JSONObject(this.headers);
            Iterator<String> iterator = jsonObject.keys();
            while (iterator.hasNext()) {
                String key = iterator.next();
                map.put(key, jsonObject.optString(key));
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return map;
    }

    private String byte2String(byte[] bytes) {
        if (bytes == null || bytes.length <= 0) {
            return "";
        }
        String result = new String(bytes, StandardCharsets.UTF_8);
        return result;
    }
}
