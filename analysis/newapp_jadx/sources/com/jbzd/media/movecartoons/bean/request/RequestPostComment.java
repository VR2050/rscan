package com.jbzd.media.movecartoons.bean.request;

/* loaded from: classes2.dex */
public class RequestPostComment {
    public String child_user_id;
    public String content;

    /* renamed from: id */
    public String f9929id;
    public String parent_id;

    public RequestPostComment(String str, String str2, String str3, String str4) {
        this.f9929id = str;
        this.content = str2;
        this.parent_id = str3;
        this.child_user_id = str4;
    }

    public String getChild_user_id() {
        return this.child_user_id;
    }

    public String getContent() {
        return this.content;
    }

    public String getId() {
        return this.f9929id;
    }

    public String getParent_id() {
        return this.parent_id;
    }

    public void setChild_user_id(String str) {
        this.child_user_id = str;
    }

    public void setContent(String str) {
        this.content = str;
    }

    public void setId(String str) {
        this.f9929id = str;
    }

    public void setParent_id(String str) {
        this.parent_id = str;
    }
}
