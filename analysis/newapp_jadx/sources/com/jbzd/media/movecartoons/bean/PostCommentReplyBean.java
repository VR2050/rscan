package com.jbzd.media.movecartoons.bean;

import java.io.Serializable;

/* loaded from: classes2.dex */
public class PostCommentReplyBean implements Serializable {
    public String content;
    public String from_uid;
    public String from_uimg;
    public String from_uname;

    /* renamed from: id */
    public String f9923id;
    public String label;
    public String reply_type;
    public String to_uid;
    public String to_uname;

    public String getContent() {
        return this.content;
    }

    public String getFrom_uid() {
        return this.from_uid;
    }

    public String getFrom_uimg() {
        return this.from_uimg;
    }

    public String getFrom_uname() {
        return this.from_uname;
    }

    public String getId() {
        return this.f9923id;
    }

    public String getLabel() {
        return this.label;
    }

    public String getReply_type() {
        return this.reply_type;
    }

    public String getTo_uid() {
        return this.to_uid;
    }

    public String getTo_uname() {
        return this.to_uname;
    }

    public void setContent(String str) {
        this.content = str;
    }

    public void setFrom_uid(String str) {
        this.from_uid = str;
    }

    public void setFrom_uimg(String str) {
        this.from_uimg = str;
    }

    public void setFrom_uname(String str) {
        this.from_uname = str;
    }

    public void setId(String str) {
        this.f9923id = str;
    }

    public void setLabel(String str) {
        this.label = str;
    }

    public void setReply_type(String str) {
        this.reply_type = str;
    }

    public void setTo_uid(String str) {
        this.to_uid = str;
    }

    public void setTo_uname(String str) {
        this.to_uname = str;
    }
}
