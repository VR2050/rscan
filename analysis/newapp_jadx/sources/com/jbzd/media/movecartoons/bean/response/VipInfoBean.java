package com.jbzd.media.movecartoons.bean.response;

import java.util.List;

/* loaded from: classes2.dex */
public class VipInfoBean {
    private List<GroupBean> group;
    private String tips;
    private String user_id;
    private String username;
    private String vip_tips;

    public List<GroupBean> getGroup() {
        return this.group;
    }

    public String getTips() {
        return this.tips;
    }

    public String getUser_id() {
        return this.user_id;
    }

    public String getUsername() {
        return this.username;
    }

    public String getVip_tips() {
        return this.vip_tips;
    }

    public void setGroup(List<GroupBean> list) {
        this.group = list;
    }

    public void setTips(String str) {
        this.tips = str;
    }

    public void setUser_id(String str) {
        this.user_id = str;
    }

    public void setUsername(String str) {
        this.username = str;
    }

    public void setVip_tips(String str) {
        this.vip_tips = str;
    }
}
