package com.bjz.comm.net.utils;

/* JADX INFO: loaded from: classes4.dex */
public class NestableRuntimeException extends RuntimeException {
    private static final long serialVersionUID = 1;
    private Throwable cause;

    public NestableRuntimeException() {
        this.cause = null;
    }

    public NestableRuntimeException(String msg) {
        super(msg);
        this.cause = null;
    }

    public NestableRuntimeException(Throwable cause) {
        this.cause = null;
        this.cause = cause;
    }

    public NestableRuntimeException(String msg, Throwable cause) {
        super(msg);
        this.cause = null;
        this.cause = cause;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.cause;
    }

    @Override // java.lang.Throwable
    public String getMessage() {
        if (super.getMessage() != null) {
            return super.getMessage();
        }
        Throwable th = this.cause;
        if (th != null) {
            return th.toString();
        }
        return null;
    }
}
