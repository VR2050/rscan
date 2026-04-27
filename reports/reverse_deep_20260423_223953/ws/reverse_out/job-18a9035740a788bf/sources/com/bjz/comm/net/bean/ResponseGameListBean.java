package com.bjz.comm.net.bean;

import java.io.Serializable;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
public class ResponseGameListBean implements Serializable {
    private int code;
    private ArrayList<MiniGameBean> data;
    private String msg;
    private String requestId;

    public int getCode() {
        return this.code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return this.msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public String getRequestId() {
        return this.requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public ArrayList<MiniGameBean> getData() {
        return this.data;
    }

    public void setData(ArrayList<MiniGameBean> data) {
        this.data = data;
    }
}
