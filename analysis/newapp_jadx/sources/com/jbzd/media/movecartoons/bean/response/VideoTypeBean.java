package com.jbzd.media.movecartoons.bean.response;

/* loaded from: classes2.dex */
public class VideoTypeBean {
    public static final String video_type_all = "";
    public static final String video_type_free = "free";
    public static final String video_type_point = "point";
    public static final String video_type_vip = "vip";
    public String key;
    public String name;

    public VideoTypeBean(String str, String str2) {
        this.key = str;
        this.name = str2;
    }
}
