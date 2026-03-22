package com.lljjcoder.style.citypickerview.model;

import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class DistrictModel {
    private String name;
    private String zipcode;

    public DistrictModel() {
    }

    public String getName() {
        return this.name;
    }

    public String getZipcode() {
        return this.zipcode;
    }

    public void setName(String str) {
        this.name = str;
    }

    public void setZipcode(String str) {
        this.zipcode = str;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("DistrictModel [name=");
        m586H.append(this.name);
        m586H.append(", zipcode=");
        return C1499a.m582D(m586H, this.zipcode, "]");
    }

    public DistrictModel(String str, String str2) {
        this.name = str;
        this.zipcode = str2;
    }
}
