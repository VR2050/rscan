package com.bjz.comm.net.base;

/* JADX INFO: loaded from: classes4.dex */
public interface DataListener<T> {
    void onError(Throwable th);

    void onResponse(T t);
}
