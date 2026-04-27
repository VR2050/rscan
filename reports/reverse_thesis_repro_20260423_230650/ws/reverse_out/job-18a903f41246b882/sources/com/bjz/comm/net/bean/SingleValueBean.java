package com.bjz.comm.net.bean;

import java.io.Serializable;

/* JADX INFO: loaded from: classes4.dex */
public class SingleValueBean implements Serializable {
    private Object Value;

    public Object getValue() {
        return this.Value;
    }

    public void setValue(String value) {
        this.Value = value;
    }
}
