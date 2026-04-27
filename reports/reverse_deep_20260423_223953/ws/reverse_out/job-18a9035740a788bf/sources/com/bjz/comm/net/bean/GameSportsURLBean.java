package com.bjz.comm.net.bean;

import android.os.Parcel;
import android.os.Parcelable;

/* JADX INFO: loaded from: classes4.dex */
public class GameSportsURLBean implements Parcelable {
    public static final Parcelable.Creator<GameSportsURLBean> CREATOR = new Parcelable.Creator<GameSportsURLBean>() { // from class: com.bjz.comm.net.bean.GameSportsURLBean.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public GameSportsURLBean createFromParcel(Parcel in) {
            return new GameSportsURLBean(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public GameSportsURLBean[] newArray(int size) {
            return new GameSportsURLBean[size];
        }
    };
    private GameSportsLoginUrlBean data;
    private String msg;
    private int status;

    public GameSportsURLBean() {
    }

    protected GameSportsURLBean(Parcel in) {
        this.status = in.readInt();
        this.msg = in.readString();
    }

    public int getStatus() {
        return this.status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMsg() {
        return this.msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public GameSportsLoginUrlBean getData() {
        return this.data;
    }

    public void setData(GameSportsLoginUrlBean data) {
        this.data = data;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(this.status);
        dest.writeString(this.msg);
    }
}
