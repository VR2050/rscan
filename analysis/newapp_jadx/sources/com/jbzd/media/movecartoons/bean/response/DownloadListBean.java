package com.jbzd.media.movecartoons.bean.response;

import java.io.Serializable;
import java.util.List;

/* loaded from: classes2.dex */
public class DownloadListBean implements Serializable {
    public static final String COMPLETED = "completed";
    public static final String DOING = "doing";
    public static final String ERROR = "error";
    public static final String UNKNOW = "unknow";
    public static final String WAIT = "wait";
    public String canvas;
    public String category;
    public String click;
    public String comment;
    private String content;
    public String description;
    public int downloadSuccessCount;
    public int downloadTotal;
    public String duration;
    private int errorCount;
    public String favorite;
    private List<String> files;
    public String height;
    public String ico;

    /* renamed from: id */
    public String f9946id;
    public String img_x;
    public String img_y;
    public String localUrl;
    public String money;
    public String name;
    public String name_tw;
    public String pay_type;
    public String status;
    private String status_show;
    public String status_text;
    public String task_id;
    public String type;
    public String width;
    public String downloadStatus = "";
    public boolean isSelect = false;
    private int successCount = 0;
    private int successIndex = 0;
}
