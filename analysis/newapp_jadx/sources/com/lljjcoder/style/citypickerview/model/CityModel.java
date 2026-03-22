package com.lljjcoder.style.citypickerview.model;

import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class CityModel {
    private List<DistrictModel> districtList;
    private String name;

    public CityModel() {
    }

    public List<DistrictModel> getDistrictList() {
        return this.districtList;
    }

    public String getName() {
        return this.name;
    }

    public void setDistrictList(List<DistrictModel> list) {
        this.districtList = list;
    }

    public void setName(String str) {
        this.name = str;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("CityModel [name=");
        m586H.append(this.name);
        m586H.append(", districtList=");
        m586H.append(this.districtList);
        m586H.append("]");
        return m586H.toString();
    }

    public CityModel(String str, List<DistrictModel> list) {
        this.name = str;
        this.districtList = list;
    }
}
