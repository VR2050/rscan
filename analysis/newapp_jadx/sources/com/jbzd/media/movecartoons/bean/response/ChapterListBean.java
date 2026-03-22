package com.jbzd.media.movecartoons.bean.response;

import java.util.List;

/* loaded from: classes2.dex */
public class ChapterListBean {
    private int book_id;
    private boolean can_play;
    private String duration;
    private boolean has_download;

    /* renamed from: id */
    private int f9935id;
    private int is_vip;
    private int label;
    private String name;
    private int original_point;
    private int paged_at;
    private List<PlansBean> plans;
    private String play;
    private int point;
    private int sort;
    private boolean user_is_vip;
    private int vip_point;

    public int getBook_id() {
        return this.book_id;
    }

    public String getDuration() {
        return this.duration;
    }

    public int getId() {
        return this.f9935id;
    }

    public int getIs_vip() {
        return this.is_vip;
    }

    public int getLabel() {
        return this.label;
    }

    public String getName() {
        return this.name;
    }

    public int getOriginal_point() {
        return this.original_point;
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

    public int getPoint() {
        return this.point;
    }

    public int getSort() {
        return this.sort;
    }

    public int getVip_point() {
        return this.vip_point;
    }

    public boolean isCan_play() {
        return this.can_play;
    }

    public boolean isHas_download() {
        return this.has_download;
    }

    public boolean isUser_is_vip() {
        return this.user_is_vip;
    }

    public void setBook_id(int i2) {
        this.book_id = i2;
    }

    public void setCan_play(boolean z) {
        this.can_play = z;
    }

    public void setDuration(String str) {
        this.duration = str;
    }

    public void setHas_download(boolean z) {
        this.has_download = z;
    }

    public void setId(int i2) {
        this.f9935id = i2;
    }

    public void setIs_vip(int i2) {
        this.is_vip = i2;
    }

    public void setLabel(int i2) {
        this.label = i2;
    }

    public void setName(String str) {
        this.name = str;
    }

    public void setOriginal_point(int i2) {
        this.original_point = i2;
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

    public void setPoint(int i2) {
        this.point = i2;
    }

    public void setSort(int i2) {
        this.sort = i2;
    }

    public void setUser_is_vip(boolean z) {
        this.user_is_vip = z;
    }

    public void setVip_point(int i2) {
        this.vip_point = i2;
    }
}
