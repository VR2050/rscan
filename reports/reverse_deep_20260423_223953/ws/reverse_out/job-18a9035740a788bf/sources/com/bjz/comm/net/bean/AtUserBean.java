package com.bjz.comm.net.bean;

import java.io.Serializable;

/* JADX INFO: loaded from: classes4.dex */
public class AtUserBean implements Serializable {
    private long accessHash;
    private String nickName;
    private String showName;
    private int userID;
    private String userName;

    public AtUserBean(String nickName, String userName, int userID, long accessHash) {
        this.nickName = nickName;
        this.userName = userName;
        this.userID = userID;
        this.accessHash = accessHash;
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

    public String toString() {
        return "AtUserBean{userID=" + this.userID + ", nickName='" + this.nickName + "', userName='" + this.userName + "', showName='" + this.showName + "', accessHash=" + this.accessHash + '}';
    }
}
