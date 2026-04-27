package com.zhy.http.okhttp.callback;

import okhttp3.Call;
import okhttp3.Request;
import okhttp3.Response;

/* JADX INFO: loaded from: classes3.dex */
public abstract class Callback<T> {
    public static Callback CALLBACK_DEFAULT = new Callback() { // from class: com.zhy.http.okhttp.callback.Callback.1
        @Override // com.zhy.http.okhttp.callback.Callback
        public Object parseNetworkResponse(Response response, int id) throws Exception {
            return null;
        }

        @Override // com.zhy.http.okhttp.callback.Callback
        public void onError(Call call, Exception e, int id) {
        }

        @Override // com.zhy.http.okhttp.callback.Callback
        public void onResponse(Object response, int id) {
        }
    };

    public abstract void onError(Call call, Exception exc, int i);

    public abstract void onResponse(T t, int i);

    public abstract T parseNetworkResponse(Response response, int i) throws Exception;

    public void onBefore(Request request, int id) {
    }

    public void onAfter(int id) {
    }

    public void inProgress(float progress, long total, int id) {
    }

    public boolean validateReponse(Response response, int id) {
        return response.isSuccessful();
    }
}
