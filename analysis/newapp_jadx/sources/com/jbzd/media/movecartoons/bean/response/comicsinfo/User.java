package com.jbzd.media.movecartoons.bean.response.comicsinfo;

import java.io.Serializable;

/* loaded from: classes2.dex */
public class User implements Serializable {
    private String balance;

    /* renamed from: id */
    private String f10013id;
    private String img;
    private String is_vip;
    private String nickname;
    private String username;

    public String getBalance() {
        return this.balance;
    }

    public String getId() {
        return this.f10013id;
    }

    public String getImg() {
        return this.img;
    }

    public String getIs_vip() {
        return this.is_vip;
    }

    public String getNickname() {
        return this.nickname;
    }

    public String getUsername() {
        return this.username;
    }

    public void setBalance(String str) {
        this.balance = str;
    }

    public void setId(String str) {
        this.f10013id = str;
    }

    public void setImg(String str) {
        this.img = str;
    }

    public void setIs_vip(String str) {
        this.is_vip = str;
    }

    public void setNickname(String str) {
        this.nickname = str;
    }

    public void setUsername(String str) {
        this.username = str;
    }
}
