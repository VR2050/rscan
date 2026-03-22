package com.jbzd.media.movecartoons.bean.response;

import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class DownloadVideoInfo {
    public static final String COMPLETED = "completed";
    public static final String DOING = "doing";
    public static final String ERROR = "error";
    public static final String UNKNOW = "unknow";
    public static final String WAIT = "wait";
    public static String separator = "AAA";
    public String content;
    public int errorCount;
    public List<String> files;
    public String status;

    /* renamed from: id */
    public String f9947id = "";
    public int successCount = 0;
    public int successIndex = 0;

    public static String getTaskID(String str, String str2) {
        return C1499a.m582D(C1499a.m586H(str), separator, str2);
    }
}
