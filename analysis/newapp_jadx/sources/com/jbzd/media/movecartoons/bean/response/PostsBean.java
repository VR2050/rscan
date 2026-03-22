package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class PostsBean implements Serializable {
    public static final String TYPE_IMAGE = "image";
    public static final String TYPE_VIDEO = "video";
    public List<ActorBean> actors;
    public List<AdBean> ads;
    private String bg_img;
    private String big_img;
    public List<CanDoBean> canDoBean;
    private String click;
    private String comment;
    private String content;
    private String date_label;
    private String deposit_txt;
    public int fans;
    public int follows;
    private String has_love;

    /* renamed from: id */
    private int f9983id;
    private List<String> img;
    private String is_ad;
    private int is_follow;
    private String is_my;
    private String is_official;
    private String link;
    private String love;
    public String movie_album_id;
    private String name;
    private String nickname;
    private String note;
    private String order_txt;
    public String result_content;
    private String rights_ico;
    private String show_submit_button;
    private String status;
    public List<StatusConfigBean> status_config;
    private String status_label;
    private String status_txt;
    public String time;
    private String tips;
    private String title;
    public String to_user_id;
    public int total_trade;
    private String type;
    private String type_label;
    private String user_id;
    private String user_img;
    private String username;
    private String video;
    private List<String> vip;
    private String watch_limit;
    private String week;

    public String getBg_img() {
        return this.bg_img;
    }

    public String getBig_img() {
        return this.big_img;
    }

    public List<CanDoBean> getCanDo() {
        return this.canDoBean;
    }

    public String getClick() {
        return this.click;
    }

    public String getComment() {
        return this.comment;
    }

    public String getContent() {
        return this.content;
    }

    public String getDate_label() {
        return this.date_label;
    }

    public String getDeposit_txt() {
        return this.deposit_txt;
    }

    public int getFans() {
        return this.fans;
    }

    public int getFollows() {
        return this.follows;
    }

    public String getHas_love() {
        return this.has_love;
    }

    public int getId() {
        return this.f9983id;
    }

    public List<String> getImg() {
        return this.img;
    }

    public boolean getIsChecking() {
        return TextUtils.equals(getStatus(), "0");
    }

    public boolean getIsMy() {
        return TextUtils.equals(getIs_my(), "y");
    }

    public boolean getIsRefuse() {
        return TextUtils.equals(getStatus(), "2");
    }

    public boolean getIsSuccess() {
        return TextUtils.equals(getStatus(), "1");
    }

    public String getIs_ad() {
        return this.is_ad;
    }

    public int getIs_follow() {
        return this.is_follow;
    }

    public String getIs_my() {
        return this.is_my;
    }

    public String getIs_official() {
        return this.is_official;
    }

    public String getLink() {
        return this.link;
    }

    public String getLove() {
        return this.love;
    }

    public String getName() {
        return this.name;
    }

    public String getNickname() {
        return this.nickname;
    }

    public String getNote() {
        return this.note;
    }

    public String getOrder_txt() {
        return this.order_txt;
    }

    public String getRights_ico() {
        return this.rights_ico;
    }

    public String getShow_submit_button() {
        return this.show_submit_button;
    }

    public String getStatus() {
        return this.status;
    }

    public List<StatusConfigBean> getStatusConfigBean() {
        return this.status_config;
    }

    public String getStatus_label() {
        return this.status_label;
    }

    public String getStatus_txt() {
        return this.status_txt;
    }

    public String getTips() {
        return this.tips;
    }

    public String getTitle() {
        return this.title;
    }

    public String getTo_user_id() {
        return this.to_user_id;
    }

    public int getTotal_trade() {
        return this.total_trade;
    }

    public String getType() {
        return this.type;
    }

    public String getType_label() {
        return this.type_label;
    }

    public String getUser_id() {
        return this.user_id;
    }

    public String getUser_img() {
        return this.user_img;
    }

    public String getUsername() {
        return this.username;
    }

    public String getVideo() {
        return this.video;
    }

    public List<String> getVip() {
        return this.vip;
    }

    public String getWatch_limit() {
        return this.watch_limit;
    }

    public String getWeek() {
        return this.week;
    }

    public void setBg_img(String str) {
        this.bg_img = str;
    }

    public void setBig_img(String str) {
        this.big_img = str;
    }

    public void setCanDo(List<CanDoBean> list) {
        this.canDoBean = list;
    }

    public void setClick(String str) {
        this.click = str;
    }

    public void setComment(String str) {
        this.comment = str;
    }

    public void setContent(String str) {
        this.content = str;
    }

    public void setDate_label(String str) {
        this.date_label = str;
    }

    public void setDeposit_txt(String str) {
        this.deposit_txt = str;
    }

    public void setFans(int i2) {
        this.fans = i2;
    }

    public void setFollows(int i2) {
        this.follows = i2;
    }

    public void setHas_love(String str) {
        this.has_love = str;
    }

    public void setId(int i2) {
        this.f9983id = i2;
    }

    public void setImg(List<String> list) {
        this.img = list;
    }

    public void setIs_ad(String str) {
        this.is_ad = str;
    }

    public void setIs_follow(int i2) {
        this.is_follow = i2;
    }

    public void setIs_my(String str) {
        this.is_my = str;
    }

    public void setIs_official(String str) {
        this.is_official = str;
    }

    public void setLink(String str) {
        this.link = str;
    }

    public void setLove(String str) {
        this.love = str;
    }

    public void setName(String str) {
        this.name = str;
    }

    public void setNickname(String str) {
        this.nickname = str;
    }

    public void setNote(String str) {
        this.note = str;
    }

    public void setOrder_txt(String str) {
        this.order_txt = str;
    }

    public void setRights_ico(String str) {
        this.rights_ico = str;
    }

    public void setShow_submit_button(String str) {
        this.show_submit_button = str;
    }

    public void setStatus(String str) {
        this.status = str;
    }

    public void setStatusConfigBean(List<StatusConfigBean> list) {
        this.status_config = list;
    }

    public void setStatus_label(String str) {
        this.status_label = str;
    }

    public void setStatus_txt(String str) {
        this.status_txt = str;
    }

    public void setTips(String str) {
        this.tips = str;
    }

    public void setTitle(String str) {
        this.title = str;
    }

    public void setTo_user_id(String str) {
        this.to_user_id = str;
    }

    public void setTotal_trade(int i2) {
        this.total_trade = i2;
    }

    public void setType(String str) {
        this.type = str;
    }

    public void setType_label(String str) {
        this.type_label = str;
    }

    public void setUser_id(String str) {
        this.user_id = str;
    }

    public void setUser_img(String str) {
        this.user_img = str;
    }

    public void setUsername(String str) {
        this.username = str;
    }

    public void setVideo(String str) {
        this.video = str;
    }

    public void setVip(List<String> list) {
        this.vip = list;
    }

    public void setWatch_limit(String str) {
        this.watch_limit = str;
    }

    public void setWeek(String str) {
        this.week = str;
    }
}
