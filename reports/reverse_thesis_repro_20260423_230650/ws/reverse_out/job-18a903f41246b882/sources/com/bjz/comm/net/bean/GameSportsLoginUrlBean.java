package com.bjz.comm.net.bean;

import android.os.Parcel;
import android.os.Parcelable;

/* JADX INFO: loaded from: classes4.dex */
public class GameSportsLoginUrlBean implements Parcelable {
    public static final Parcelable.Creator<GameSportsLoginUrlBean> CREATOR = new Parcelable.Creator<GameSportsLoginUrlBean>() { // from class: com.bjz.comm.net.bean.GameSportsLoginUrlBean.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public GameSportsLoginUrlBean createFromParcel(Parcel in) {
            return new GameSportsLoginUrlBean(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public GameSportsLoginUrlBean[] newArray(int size) {
            return new GameSportsLoginUrlBean[size];
        }
    };
    private String loginurl;

    public GameSportsLoginUrlBean() {
    }

    protected GameSportsLoginUrlBean(Parcel in) {
        this.loginurl = in.readString();
    }

    public String getLoginurl() {
        return this.loginurl;
    }

    public void setLoginurl(String loginurl) {
        this.loginurl = loginurl;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(this.loginurl);
    }
}
