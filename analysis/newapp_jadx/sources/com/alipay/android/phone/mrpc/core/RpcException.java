package com.alipay.android.phone.mrpc.core;

import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class RpcException extends RuntimeException {
    private static final long serialVersionUID = -2875437994101380406L;
    private int mCode;
    private String mMsg;
    private String mOperationType;

    public RpcException(Integer num, String str) {
        super(m3647a(num, str));
        this.mCode = num.intValue();
        this.mMsg = str;
    }

    public RpcException(Integer num, String str, Throwable th) {
        super(m3647a(num, str), th);
        this.mCode = num.intValue();
        this.mMsg = str;
    }

    public RpcException(Integer num, Throwable th) {
        super(th);
        this.mCode = num.intValue();
    }

    public RpcException(String str) {
        super(str);
        this.mCode = 0;
        this.mMsg = str;
    }

    /* renamed from: a */
    private static String m3647a(Integer num, String str) {
        StringBuilder m586H = C1499a.m586H("RPCException: ");
        if (num != null) {
            m586H.append("[");
            m586H.append(num);
            m586H.append("]");
        }
        m586H.append(" : ");
        if (str != null) {
            m586H.append(str);
        }
        return m586H.toString();
    }

    public int getCode() {
        return this.mCode;
    }

    public String getMsg() {
        return this.mMsg;
    }

    public String getOperationType() {
        return this.mOperationType;
    }

    public void setOperationType(String str) {
        this.mOperationType = str;
    }
}
