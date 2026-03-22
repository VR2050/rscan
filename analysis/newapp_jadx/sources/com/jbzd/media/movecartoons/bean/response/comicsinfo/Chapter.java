package com.jbzd.media.movecartoons.bean.response.comicsinfo;

import android.os.Parcel;
import android.os.Parcelable;
import java.io.Serializable;

/* loaded from: classes2.dex */
public class Chapter implements Serializable, Parcelable {
    public static final Parcelable.Creator<Chapter> CREATOR = new Parcelable.Creator<Chapter>() { // from class: com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public Chapter createFromParcel(Parcel parcel) {
            return new Chapter(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public Chapter[] newArray(int i2) {
            return new Chapter[i2];
        }
    };
    public String button_text;
    public String can_view;

    /* renamed from: id */
    public String f10008id;
    public String img;
    public String is_audio;
    public String money;
    public String name;
    public String show_adv_full;
    public String type;

    public Chapter() {
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeString(this.img);
        parcel.writeString(this.can_view);
        parcel.writeString(this.money);
        parcel.writeString(this.name);
        parcel.writeString(this.f10008id);
        parcel.writeString(this.is_audio);
        parcel.writeString(this.button_text);
        parcel.writeString(this.type);
        parcel.writeString(this.show_adv_full);
    }

    public Chapter(String str, String str2, String str3, String str4, String str5, String str6, String str7) {
        this.img = str;
        this.can_view = str2;
        this.money = str3;
        this.name = str4;
        this.f10008id = str5;
        this.button_text = str6;
        this.type = str7;
    }

    public Chapter(Parcel parcel) {
        this.img = parcel.readString();
        this.can_view = parcel.readString();
        this.money = parcel.readString();
        this.name = parcel.readString();
        this.f10008id = parcel.readString();
        this.is_audio = parcel.readString();
        this.button_text = parcel.readString();
        this.type = parcel.readString();
        this.show_adv_full = parcel.readString();
    }
}
