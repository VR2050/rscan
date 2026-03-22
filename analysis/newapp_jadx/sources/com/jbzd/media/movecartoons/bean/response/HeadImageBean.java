package com.jbzd.media.movecartoons.bean.response;

import java.util.List;

/* loaded from: classes2.dex */
public class HeadImageBean {
    public List<HeadImagesBean> head_images;

    public static class HeadImagesBean {
        public String img;
        public String value;
        public boolean isUpload = false;
        public boolean isChecked = false;
    }
}
