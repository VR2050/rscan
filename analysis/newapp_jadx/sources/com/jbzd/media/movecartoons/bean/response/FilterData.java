package com.jbzd.media.movecartoons.bean.response;

import android.os.Parcel;
import android.os.Parcelable;
import java.io.Serializable;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class FilterData implements Serializable, Parcelable {
    public static final Parcelable.Creator<FilterData> CREATOR = new Parcelable.Creator<FilterData>() { // from class: com.jbzd.media.movecartoons.bean.response.FilterData.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public FilterData createFromParcel(Parcel parcel) {
            return new FilterData(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public FilterData[] newArray(int i2) {
            return new FilterData[i2];
        }
    };
    private String code;
    public boolean isSelected;
    private String name;
    private String value;
    public Integer watch_limit;

    public FilterData(String str, String str2, String str3) {
        this.isSelected = false;
        this.watch_limit = 0;
        this.code = str;
        this.name = str2;
        this.value = str3;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getCode() {
        return this.code;
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    public void setCode(String str) {
        this.code = str;
    }

    public void setName(String str) {
        this.name = str;
    }

    public void setValue(String str) {
        this.value = str;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("FilterData{code='");
        m586H.append(this.code);
        m586H.append('\'');
        m586H.append(", name='");
        m586H.append(this.name);
        m586H.append('\'');
        m586H.append(", value='");
        m586H.append(this.value);
        m586H.append('\'');
        m586H.append('}');
        return m586H.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.code);
        parcel.writeString(this.name);
        parcel.writeString(this.value);
    }

    public FilterData(String str, String str2, String str3, boolean z) {
        this.isSelected = false;
        this.watch_limit = 0;
        this.name = str;
        this.value = str2;
        this.code = str3;
        this.isSelected = z;
    }

    public FilterData(Parcel parcel) {
        this.isSelected = false;
        this.watch_limit = 0;
        this.code = parcel.readString();
        this.name = parcel.readString();
        this.value = parcel.readString();
    }
}
