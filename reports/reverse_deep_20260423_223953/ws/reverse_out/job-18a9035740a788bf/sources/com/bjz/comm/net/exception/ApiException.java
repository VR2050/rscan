package com.bjz.comm.net.exception;

import androidx.annotation.Nullable;
import java.io.IOException;

/* JADX INFO: loaded from: classes4.dex */
public class ApiException extends IOException {
    private int code;
    private final String msg;

    public ApiException(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    @Override // java.lang.Throwable
    @Nullable
    public String getMessage() {
        String str = this.msg;
        if (str != null && !str.equals("")) {
            return this.msg;
        }
        return super.getMessage();
    }

    public int getCode() {
        return this.code;
    }
}
