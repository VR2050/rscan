package com.jbzd.media.movecartoons.bean.response;

import android.text.TextUtils;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public class UploadBean implements Serializable {
    public static final String COMPLETED = "completed";
    public static final String DOING = "doing";
    public static final String ERROR = "error";
    public static final String PUBLISHED = "published";
    public static final String PUBLISH_ERROR = "publish_error";
    public static final String WAIT = "wait";
    private static final long serialVersionUID = 1008826607851521180L;
    public String canvas;
    public String duration;

    /* renamed from: id */
    public Long f9990id;
    public String image_path;
    public String img;
    public String img_show;
    public boolean is_draft;
    public String link;
    public String m3u8_url;
    public String point;
    public String preview;
    public String preview_m3u8_url;
    public int progress_slice;
    public String quality;
    public String status;
    public String tag_id;
    public String tag_names;
    public long time;
    public String title;
    public int total_slices;
    public String video_path;

    public UploadBean(Long l2, String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, String str11, String str12, String str13, String str14, String str15, long j2, boolean z, String str16, int i2, int i3) {
        this.img = "";
        this.preview = "1";
        this.preview_m3u8_url = "";
        this.m3u8_url = "";
        this.tag_names = "";
        this.f9990id = l2;
        this.title = str;
        this.img = str2;
        this.preview = str3;
        this.preview_m3u8_url = str4;
        this.m3u8_url = str5;
        this.duration = str6;
        this.quality = str7;
        this.img_show = str8;
        this.point = str9;
        this.tag_id = str10;
        this.tag_names = str11;
        this.link = str12;
        this.canvas = str13;
        this.video_path = str14;
        this.image_path = str15;
        this.time = j2;
        this.is_draft = z;
        this.status = str16;
        this.total_slices = i2;
        this.progress_slice = i3;
    }

    public String getCanvas() {
        return this.canvas;
    }

    public String getDuration() {
        return this.duration;
    }

    public Long getId() {
        return this.f9990id;
    }

    public String getIdStr() {
        return String.valueOf(this.f9990id);
    }

    public String getImage_path() {
        return this.image_path;
    }

    public String getImg() {
        return this.img;
    }

    public String getImg_show() {
        return this.img_show;
    }

    public boolean getIsMoneyVideo() {
        String str = this.point;
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        try {
            Intrinsics.checkNotNull(str);
            return Double.parseDouble(str) > ShadowDrawableWrapper.COS_45;
        } catch (Exception unused) {
            return false;
        }
    }

    public boolean getIs_draft() {
        return this.is_draft;
    }

    public String getLink() {
        return this.link;
    }

    public String getM3u8_url() {
        return this.m3u8_url;
    }

    public String getPoint() {
        return this.point;
    }

    public String getPreview() {
        return this.preview;
    }

    public String getPreview_m3u8_url() {
        return this.preview_m3u8_url;
    }

    public int getProgress_slice() {
        return this.progress_slice;
    }

    public String getQuality() {
        return this.quality;
    }

    public String getStatus() {
        return this.status;
    }

    public String getTag_id() {
        return this.tag_id;
    }

    public String getTag_names() {
        return this.tag_names;
    }

    public long getTime() {
        return this.time;
    }

    public String getTitle() {
        return this.title;
    }

    public int getTotal_slices() {
        return this.total_slices;
    }

    public String getVideo_path() {
        return this.video_path;
    }

    public boolean isLong() {
        return TextUtils.equals("long", this.canvas);
    }

    public boolean isNeedUploadVideo() {
        return (TextUtils.equals(this.status, "completed") || TextUtils.equals(this.status, PUBLISHED) || TextUtils.equals(this.status, PUBLISH_ERROR)) ? false : true;
    }

    public void setCanvas(String str) {
        this.canvas = str;
    }

    public void setDuration(String str) {
        this.duration = str;
    }

    public void setId(Long l2) {
        this.f9990id = l2;
    }

    public void setImage_path(String str) {
        this.image_path = str;
    }

    public void setImg(String str) {
        this.img = str;
    }

    public void setImg_show(String str) {
        this.img_show = str;
    }

    public void setIs_draft(boolean z) {
        this.is_draft = z;
    }

    public void setLink(String str) {
        this.link = str;
    }

    public void setM3u8_url(String str) {
        this.m3u8_url = str;
    }

    public void setPoint(String str) {
        this.point = str;
    }

    public void setPreview(String str) {
        this.preview = str;
    }

    public void setPreview_m3u8_url(String str) {
        this.preview_m3u8_url = str;
    }

    public void setProgress_slice(int i2) {
        this.progress_slice = i2;
    }

    public void setQuality(String str) {
        this.quality = str;
    }

    public void setStatus(String str) {
        this.status = str;
    }

    public void setTag_id(String str) {
        this.tag_id = str;
    }

    public void setTag_names(String str) {
        this.tag_names = str;
    }

    public void setTime(long j2) {
        this.time = j2;
    }

    public void setTitle(String str) {
        this.title = str;
    }

    public void setTotal_slices(int i2) {
        this.total_slices = i2;
    }

    public void setVideo_path(String str) {
        this.video_path = str;
    }

    public UploadBean() {
        this.img = "";
        this.preview = "1";
        this.preview_m3u8_url = "";
        this.m3u8_url = "";
        this.tag_names = "";
    }
}
