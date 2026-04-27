package com.bjz.comm.net.base;

import androidx.annotation.Nullable;
import okhttp3.Call;
import okhttp3.HttpUrl;
import okhttp3.Request;

/* JADX INFO: loaded from: classes4.dex */
public abstract class CallFactoryProxy implements Call.Factory {
    private final Call.Factory delegate;

    @Nullable
    protected abstract HttpUrl getNewUrl(Request request);

    public CallFactoryProxy(Call.Factory delegate) {
        this.delegate = delegate;
    }

    @Override // okhttp3.Call.Factory
    public Call newCall(Request request) {
        HttpUrl newHttpUrl = getNewUrl(request);
        if (newHttpUrl != null) {
            Request newRequest = request.newBuilder().url(newHttpUrl).build();
            return this.delegate.newCall(newRequest);
        }
        return this.delegate.newCall(request);
    }
}
