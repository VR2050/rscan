package com.bjz.comm.net.utils;

import com.google.gson.Gson;
import java.util.HashMap;
import java.util.Map;
import okhttp3.MediaType;
import okhttp3.RequestBody;

/* JADX INFO: loaded from: classes4.dex */
public class JsonCreateUtils {
    public static MapForJsonObject build() {
        return new MapForJsonObject();
    }

    public static class MapForJsonObject {
        Map<String, Object> map = new HashMap();
        Gson gson = new Gson();

        public MapForJsonObject addParam(String strKey, Object obj) {
            this.map.put(strKey, obj);
            return this;
        }

        public RequestBody getHttpBody() {
            String json = this.gson.toJson(this.map);
            return RequestBody.create(MediaType.parse("application/json;charset=utf-8"), json);
        }

        public String getJsonString() {
            return this.gson.toJson(this.map);
        }
    }
}
