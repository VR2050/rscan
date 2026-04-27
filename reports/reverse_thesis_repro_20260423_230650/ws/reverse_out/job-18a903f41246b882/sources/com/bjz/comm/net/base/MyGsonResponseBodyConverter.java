package com.bjz.comm.net.base;

import com.bjz.comm.net.exception.ApiException;
import com.google.gson.Gson;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import okhttp3.MediaType;
import okhttp3.ResponseBody;
import org.json.JSONObject;
import retrofit2.Converter;

/* JADX INFO: loaded from: classes4.dex */
public class MyGsonResponseBodyConverter<T> implements Converter<ResponseBody, T> {
    private static final Charset UTF_8 = Charset.forName("UTF-8");
    private final TypeAdapter<T> adapter;
    private final Gson gson;

    MyGsonResponseBodyConverter(Gson gson, TypeAdapter<T> adapter) {
        this.gson = gson;
        this.adapter = adapter;
    }

    @Override // retrofit2.Converter
    public T convert(ResponseBody value) throws IOException {
        String response = value.string();
        int code = 0;
        try {
            try {
                JSONObject object = new JSONObject(response);
                if (!object.isNull("State")) {
                    code = object.optInt("State");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (code == 400) {
                throw new ApiException(code, "Token has expired.");
            }
            MediaType mediaType = value.contentType();
            Charset charset = mediaType != null ? mediaType.charset(UTF_8) : UTF_8;
            InputStream inputStream = new ByteArrayInputStream(response.getBytes());
            JsonReader jsonReader = this.gson.newJsonReader(new InputStreamReader(inputStream, charset));
            return this.adapter.read2(jsonReader);
        } finally {
            value.close();
        }
    }
}
