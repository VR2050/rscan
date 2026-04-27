package com.bjz.comm.net.bean;

import java.io.Serializable;

/* JADX INFO: loaded from: classes4.dex */
public class FcIgnoreUserBean implements Serializable {
    private long CreateAt;
    private long CreateBy;
    private long ID;
    private long IgnoreID;
    private int Look;
    private long UserID;

    public FcIgnoreUserBean() {
    }

    public FcIgnoreUserBean(long userID, int look) {
        this.UserID = userID;
        this.Look = look;
    }

    public long getCreateAt() {
        return this.CreateAt;
    }

    public void setCreateAt(long createAt) {
        this.CreateAt = createAt;
    }

    public long getCreateBy() {
        return this.CreateBy;
    }

    public void setCreateBy(long createBy) {
        this.CreateBy = createBy;
    }

    public long getID() {
        return this.ID;
    }

    public void setID(long ID) {
        this.ID = ID;
    }

    public long getIgnoreID() {
        return this.IgnoreID;
    }

    public void setIgnoreID(long ignoreID) {
        this.IgnoreID = ignoreID;
    }

    public int getLook() {
        return this.Look;
    }

    public void setLook(int look) {
        this.Look = look;
    }

    public long getUserID() {
        return this.UserID;
    }

    public void setUserID(long userID) {
        this.UserID = userID;
    }

    public String toString() {
        return "FcIgnoreUserBean{CreateAt=" + this.CreateAt + ", CreateBy=" + this.CreateBy + ", ID=" + this.ID + ", IgnoreID=" + this.IgnoreID + ", Look=" + this.Look + ", UserID=" + this.UserID + '}';
    }
}
