package com.jbzd.media.movecartoons.bean;

import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class CommentListBean implements Serializable {
    public List<?> child;
    public String child_num;
    public String content;
    public String has_love;

    /* renamed from: id */
    public String f9922id;
    public String img;
    public String label;
    public String love;
    public String nickname;
    public String user_id;

    public List<?> getChild() {
        return this.child;
    }

    public String getChild_num() {
        return this.child_num;
    }

    public String getContent() {
        return this.content;
    }

    public String getHas_love() {
        return this.has_love;
    }

    public String getId() {
        return this.f9922id;
    }

    public String getImg() {
        return this.img;
    }

    public String getLabel() {
        return this.label;
    }

    public String getLove() {
        return this.love;
    }

    public String getNickname() {
        return this.nickname;
    }

    public String getUser_id() {
        return this.user_id;
    }

    public void setChild(List<?> list) {
        this.child = list;
    }

    public void setChild_num(String str) {
        this.child_num = str;
    }

    public void setContent(String str) {
        this.content = str;
    }

    public void setHas_love(String str) {
        this.has_love = str;
    }

    public void setId(String str) {
        this.f9922id = str;
    }

    public void setImg(String str) {
        this.img = str;
    }

    public void setLabel(String str) {
        this.label = str;
    }

    public void setLove(String str) {
        this.love = str;
    }

    public void setNickname(String str) {
        this.nickname = str;
    }

    public void setUser_id(String str) {
        this.user_id = str;
    }
}
