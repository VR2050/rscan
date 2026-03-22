package com.jbzd.media.movecartoons.bean.response;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class VideoStatusBean {
    public String status;
    public String statusTxt;

    public VideoStatusBean() {
    }

    public static List<VideoStatusBean> getStatusList() {
        ArrayList arrayList = new ArrayList();
        arrayList.add(new VideoStatusBean("", "综合"));
        arrayList.add(new VideoStatusBean("0", "审核中"));
        arrayList.add(new VideoStatusBean("-1,1", "已发布"));
        arrayList.add(new VideoStatusBean("-2", "未通过"));
        return arrayList;
    }

    public VideoStatusBean(String str, String str2) {
        this.status = str;
        this.statusTxt = str2;
    }
}
