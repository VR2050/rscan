package com.jbzd.media.movecartoons.bean.response;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class PostStatusBean {
    public String status;
    public String statusTxt;

    public PostStatusBean() {
    }

    public static List<VideoStatusBean> getStatusList() {
        ArrayList arrayList = new ArrayList();
        arrayList.add(new VideoStatusBean("1", "已发布"));
        arrayList.add(new VideoStatusBean("0", "待审核"));
        arrayList.add(new VideoStatusBean("2", "审核失败"));
        return arrayList;
    }

    public PostStatusBean(String str, String str2) {
        this.status = str;
        this.statusTxt = str2;
    }
}
