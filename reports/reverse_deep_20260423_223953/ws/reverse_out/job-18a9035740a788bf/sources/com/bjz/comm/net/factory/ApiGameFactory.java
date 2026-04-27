package com.bjz.comm.net.factory;

import android.text.TextUtils;
import android.util.Log;
import androidx.annotation.Nullable;
import com.bjz.comm.net.BuildVars;
import com.bjz.comm.net.api.ApiMiniGame;
import com.bjz.comm.net.base.CallFactoryProxy;
import com.bjz.comm.net.base.MyGsonConverterFactory;
import com.bjz.comm.net.interceptor.HeaderInterceptor;
import com.bjz.comm.net.utils.HttpUtils;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.logging.HttpLoggingInterceptor;
import retrofit2.Retrofit;
import retrofit2.adapter.rxjava2.RxJava2CallAdapterFactory;

/* JADX INFO: loaded from: classes4.dex */
public class ApiGameFactory {
    private static ApiGameFactory mInstance;
    private final String TAG = ApiGameFactory.class.getSimpleName();
    private ApiMiniGame mApiMiniGame;
    private final Retrofit mRetrofit;

    public static ApiGameFactory getInstance() {
        if (mInstance == null) {
            synchronized (ApiGameFactory.class) {
                if (mInstance == null) {
                    mInstance = new ApiGameFactory();
                }
            }
        }
        return mInstance;
    }

    private ApiGameFactory() {
        OkHttpClient.Builder builder = new OkHttpClient().newBuilder();
        builder.connectTimeout(60L, TimeUnit.SECONDS).writeTimeout(60L, TimeUnit.SECONDS).readTimeout(60L, TimeUnit.SECONDS).protocols(Collections.unmodifiableList(Arrays.asList(Protocol.HTTP_2, Protocol.HTTP_1_1))).addInterceptor(new HeaderInterceptor());
        if (BuildVars.LOG_VERSION) {
            HttpLoggingInterceptor loggingInterceptor = new HttpLoggingInterceptor();
            loggingInterceptor.setLevel(HttpLoggingInterceptor.Level.BODY);
            builder.addInterceptor(loggingInterceptor);
        }
        this.mRetrofit = new Retrofit.Builder().baseUrl(HttpUtils.getInstance().getGameBaseUrl()).addConverterFactory(MyGsonConverterFactory.create()).addCallAdapterFactory(RxJava2CallAdapterFactory.create()).callFactory(new CallFactoryProxy(builder.build()) { // from class: com.bjz.comm.net.factory.ApiGameFactory.1
            @Override // com.bjz.comm.net.base.CallFactoryProxy
            @Nullable
            protected HttpUrl getNewUrl(Request request) {
                Headers headers = request.headers();
                if (headers != null && headers.size() > 0 && TextUtils.equals(headers.get("RequestUrl"), "self")) {
                    return null;
                }
                HttpUrl requestHttpUrl = request.url();
                if (BuildVars.DEBUG_VERSION) {
                    Log.d(ApiGameFactory.this.TAG, "requestGameUrl == " + requestHttpUrl.host());
                }
                HttpUrl newBaseUrl = HttpUrl.parse(HttpUtils.getInstance().getGameBaseUrl());
                if (TextUtils.equals(requestHttpUrl.host(), newBaseUrl.host())) {
                    return null;
                }
                if (BuildVars.DEBUG_VERSION) {
                    Log.d(ApiGameFactory.this.TAG, "newBaseGameUrl == " + newBaseUrl.host());
                }
                HttpUrl newHttpUrl = requestHttpUrl.newBuilder().scheme(newBaseUrl.scheme()).host(newBaseUrl.host()).port(newBaseUrl.port()).build();
                return newHttpUrl;
            }
        }).build();
    }

    public ApiMiniGame getApiMiniGame() {
        if (this.mApiMiniGame == null) {
            this.mApiMiniGame = (ApiMiniGame) this.mRetrofit.create(ApiMiniGame.class);
        }
        return this.mApiMiniGame;
    }
}
