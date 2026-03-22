package com.jbzd.media.movecartoons.bean.response;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class InfoBean {
    private String author;
    private int book_id;
    private String chapter_name;
    private int chapter_num;
    private ArrayList<ClassifyBean> classify;
    private String desc;
    private boolean has_download;

    /* renamed from: id */
    private int f9964id;
    private String img;
    private boolean is_follow;
    private boolean is_love;
    private boolean is_mine;
    private int label;
    private String link;
    private String name;
    private int paged_at;
    private List<PlansBean> plans;
    private String play;
    public PlayingTrackBean playing_track;
    private String score;
    private String serial_txt;
    private int sort;
    private String subtitle;
    private int user_id;
    private String user_img;
    private boolean user_is_vip;
    private String user_name;

    public String getAuthor() {
        return this.author;
    }

    public int getBook_id() {
        return this.book_id;
    }

    public String getChapter_name() {
        return this.chapter_name;
    }

    public int getChapter_num() {
        return this.chapter_num;
    }

    public ArrayList<ClassifyBean> getClassify() {
        return this.classify;
    }

    public String getDesc() {
        return this.desc;
    }

    public int getId() {
        return this.f9964id;
    }

    public String getImg() {
        return this.img;
    }

    public int getLabel() {
        return this.label;
    }

    public String getLink() {
        return this.link;
    }

    public boolean getLove() {
        return this.is_love;
    }

    public String getName() {
        return this.name;
    }

    public int getPaged_at() {
        return this.paged_at;
    }

    public List<PlansBean> getPlans() {
        return this.plans;
    }

    public String getPlay() {
        return this.play;
    }

    public PlayingTrackBean getPlaying_track() {
        return this.playing_track;
    }

    public String getScore() {
        return this.score;
    }

    public String getSerial_txt() {
        return this.serial_txt;
    }

    public int getSort() {
        return this.sort;
    }

    public String getSubtitle() {
        return this.subtitle;
    }

    public int getUser_id() {
        return this.user_id;
    }

    public String getUser_img() {
        return this.user_img;
    }

    public String getUser_name() {
        return this.user_name;
    }

    public boolean isHas_download() {
        return this.has_download;
    }

    public boolean isIs_follow() {
        return this.is_follow;
    }

    public boolean isIs_love() {
        return this.is_love;
    }

    public boolean isIs_mine() {
        return this.is_mine;
    }

    public boolean isUser_is_vip() {
        return this.user_is_vip;
    }

    public void setAuthor(String str) {
        this.author = str;
    }

    public void setBook_id(int i2) {
        this.book_id = i2;
    }

    public void setChapter_name(String str) {
        this.chapter_name = str;
    }

    public void setChapter_num(int i2) {
        this.chapter_num = i2;
    }

    public void setClassify(ArrayList<ClassifyBean> arrayList) {
        this.classify = arrayList;
    }

    public void setDesc(String str) {
        this.desc = str;
    }

    public void setHas_download(boolean z) {
        this.has_download = z;
    }

    public void setId(int i2) {
        this.f9964id = i2;
    }

    public void setImg(String str) {
        this.img = str;
    }

    public void setIs_follow(boolean z) {
        this.is_follow = z;
    }

    public void setIs_love(boolean z) {
        this.is_love = z;
    }

    public void setIs_mine(boolean z) {
        this.is_mine = z;
    }

    public void setLabel(int i2) {
        this.label = i2;
    }

    public void setLink(String str) {
        this.link = str;
    }

    public void setLove(boolean z) {
        this.is_love = z;
    }

    public void setName(String str) {
        this.name = str;
    }

    public void setPaged_at(int i2) {
        this.paged_at = i2;
    }

    public void setPlans(List<PlansBean> list) {
        this.plans = list;
    }

    public void setPlay(String str) {
        this.play = str;
    }

    public void setPlaying_track(PlayingTrackBean playingTrackBean) {
        this.playing_track = playingTrackBean;
    }

    public void setScore(String str) {
        this.score = str;
    }

    public void setSerial_txt(String str) {
        this.serial_txt = str;
    }

    public void setSort(int i2) {
        this.sort = i2;
    }

    public void setSubtitle(String str) {
        this.subtitle = str;
    }

    public void setUser_id(int i2) {
        this.user_id = i2;
    }

    public void setUser_img(String str) {
        this.user_img = str;
    }

    public void setUser_is_vip(boolean z) {
        this.user_is_vip = z;
    }

    public void setUser_name(String str) {
        this.user_name = str;
    }
}
