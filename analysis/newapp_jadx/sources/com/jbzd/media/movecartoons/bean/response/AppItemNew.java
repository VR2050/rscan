package com.jbzd.media.movecartoons.bean.response;

import java.io.Serializable;
import p005b.p006a.p007a.p008a.p009a.C0843e0;

/* loaded from: classes2.dex */
public class AppItemNew implements Serializable {
    public String android_url;
    public String category;
    public String description;
    public String download;
    public long downloadId = 0;
    public String downloadShow;

    /* renamed from: id */
    public String f9930id;
    public String image;
    public String ios_url;
    public String name;

    public String getAndroid_url() {
        return this.android_url;
    }

    public String getCategory() {
        return this.category;
    }

    public String getDescription() {
        return this.description;
    }

    public String getDownload() {
        return this.download;
    }

    public long getDownloadId() {
        return this.downloadId;
    }

    public String getDownloadShow() {
        String m182a = C0843e0.m182a(this.download);
        this.downloadShow = m182a;
        return m182a;
    }

    public String getId() {
        return this.f9930id;
    }

    public String getImage() {
        return this.image;
    }

    public String getIos_url() {
        return this.ios_url;
    }

    public String getName() {
        return this.name;
    }

    public void setAndroid_url(String str) {
        this.android_url = str;
    }

    public void setCategory(String str) {
        this.category = str;
    }

    public void setDescription(String str) {
        this.description = str;
    }

    public void setDownload(String str) {
        this.download = str;
    }

    public void setDownloadId(long j2) {
        this.downloadId = j2;
    }

    public void setId(String str) {
        this.f9930id = str;
    }

    public void setImage(String str) {
        this.image = str;
    }

    public void setIos_url(String str) {
        this.ios_url = str;
    }

    public void setName(String str) {
        this.name = str;
    }
}
