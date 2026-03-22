package com.jbzd.media.movecartoons.bean.request;

import com.alibaba.fastjson.annotation.JSONField;
import java.io.Serializable;

/* loaded from: classes2.dex */
public class RequestOpenStream implements Serializable {
    private String game_code;
    private String image;

    @JSONField(name = "live_id")
    private String liveId;
    private String name;
    private String password;
    private String price;
    private String time_code;
    private String type = "public";

    public String getGame_code() {
        return this.game_code;
    }

    public String getImage() {
        return this.image;
    }

    public String getLiveId() {
        return this.liveId;
    }

    public String getName() {
        return this.name;
    }

    public String getPassword() {
        return this.password;
    }

    public String getPrice() {
        return this.price;
    }

    public String getTime_code() {
        return this.time_code;
    }

    public String getType() {
        return this.type;
    }

    public void setGame_code(String str) {
        this.game_code = str;
    }

    public void setImage(String str) {
        this.image = str;
    }

    public void setLiveId(String str) {
        this.liveId = str;
    }

    public void setName(String str) {
        this.name = str;
    }

    public void setPassword(String str) {
        this.password = str;
    }

    public void setPrice(String str) {
        this.price = str;
    }

    public void setTime_code(String str) {
        this.time_code = str;
    }

    public void setType(String str) {
        this.type = str;
    }
}
