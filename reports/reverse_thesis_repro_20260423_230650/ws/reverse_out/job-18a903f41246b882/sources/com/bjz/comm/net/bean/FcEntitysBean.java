package com.bjz.comm.net.bean;

import java.io.Serializable;

/* JADX INFO: loaded from: classes4.dex */
public class FcEntitysBean implements Serializable {
    private long accessHash;
    private String nickName;
    private int offsetEnd;
    private int offsetStart;
    private String showName;
    private int userID;
    private String userName;

    public FcEntitysBean(int userID, String nickName, String userName, String showName, long accessHash, int offsetStart, int offsetEnd) {
        this.userID = userID;
        this.nickName = nickName;
        this.userName = userName;
        this.showName = showName;
        this.accessHash = accessHash;
        this.offsetStart = offsetStart;
        this.offsetEnd = offsetEnd;
    }

    public int getUserID() {
        return this.userID;
    }

    public void setUserID(int userID) {
        this.userID = userID;
    }

    public String getNickName() {
        return this.nickName;
    }

    public void setNickName(String nickName) {
        this.nickName = nickName;
    }

    public String getUserName() {
        return this.userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getShowName() {
        return this.showName;
    }

    public void setShowName(String showName) {
        this.showName = showName;
    }

    public long getAccessHash() {
        return this.accessHash;
    }

    public void setAccessHash(long accessHash) {
        this.accessHash = accessHash;
    }

    public int getOffsetStart() {
        return this.offsetStart;
    }

    public void setOffsetStart(int offsetStart) {
        this.offsetStart = offsetStart;
    }

    public int getOffsetEnd() {
        return this.offsetEnd;
    }

    public void setOffsetEnd(int offsetEnd) {
        this.offsetEnd = offsetEnd;
    }
}
