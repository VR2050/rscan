package com.zhy.http.okhttp.utils;

/* JADX INFO: loaded from: classes3.dex */
public class Exceptions {
    public static void illegalArgument(String msg, Object... params) {
        throw new IllegalArgumentException(String.format(msg, params));
    }
}
