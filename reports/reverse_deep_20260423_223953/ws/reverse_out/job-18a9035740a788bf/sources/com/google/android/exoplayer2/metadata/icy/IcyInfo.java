package com.google.android.exoplayer2.metadata.icy;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.util.Util;

/* JADX INFO: loaded from: classes2.dex */
public final class IcyInfo implements Metadata.Entry {
    public static final Parcelable.Creator<IcyInfo> CREATOR = new Parcelable.Creator<IcyInfo>() { // from class: com.google.android.exoplayer2.metadata.icy.IcyInfo.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public IcyInfo createFromParcel(Parcel in) {
            return new IcyInfo(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public IcyInfo[] newArray(int size) {
            return new IcyInfo[size];
        }
    };
    public final String title;
    public final String url;

    public IcyInfo(String title, String url) {
        this.title = title;
        this.url = url;
    }

    IcyInfo(Parcel in) {
        this.title = in.readString();
        this.url = in.readString();
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        IcyInfo other = (IcyInfo) obj;
        return Util.areEqual(this.title, other.title) && Util.areEqual(this.url, other.url);
    }

    public int hashCode() {
        int i = 17 * 31;
        String str = this.title;
        int result = i + (str != null ? str.hashCode() : 0);
        int result2 = result * 31;
        String str2 = this.url;
        return result2 + (str2 != null ? str2.hashCode() : 0);
    }

    public String toString() {
        return "ICY: title=\"" + this.title + "\", url=\"" + this.url + "\"";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(this.title);
        dest.writeString(this.url);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }
}
