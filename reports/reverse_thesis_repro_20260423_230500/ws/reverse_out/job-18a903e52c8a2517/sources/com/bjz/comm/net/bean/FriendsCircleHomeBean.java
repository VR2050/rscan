package com.bjz.comm.net.bean;

import java.io.Serializable;
import java.util.List;

/* JADX INFO: loaded from: classes4.dex */
public class FriendsCircleHomeBean implements Serializable {
    int avatarId;
    int imageId;
    String name;
    String nickname;
    List<String> pics;

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getNickname() {
        return this.nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public int getImageId() {
        return this.imageId;
    }

    public void setImageId(int imageId) {
        this.imageId = imageId;
    }

    public int getAvatarId() {
        return this.avatarId;
    }

    public void setAvatarId(int avatarId) {
        this.avatarId = avatarId;
    }

    public List<String> getPics() {
        return this.pics;
    }

    public void setPics(List<String> pics) {
        this.pics = pics;
    }
}
