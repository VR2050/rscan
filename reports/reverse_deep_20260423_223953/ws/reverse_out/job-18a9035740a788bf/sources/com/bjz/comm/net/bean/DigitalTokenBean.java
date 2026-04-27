package com.bjz.comm.net.bean;

import android.os.Parcel;
import android.os.Parcelable;

/* JADX INFO: loaded from: classes4.dex */
public class DigitalTokenBean implements Parcelable {
    public static final Parcelable.Creator<DigitalTokenBean> CREATOR = new Parcelable.Creator<DigitalTokenBean>() { // from class: com.bjz.comm.net.bean.DigitalTokenBean.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public DigitalTokenBean createFromParcel(Parcel in) {
            return new DigitalTokenBean(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public DigitalTokenBean[] newArray(int size) {
            return new DigitalTokenBean[size];
        }
    };
    private String clientNonce;
    private boolean digitalWallet;
    private int expire;
    private int id;
    private String serverNonce;
    private String token;

    public DigitalTokenBean() {
    }

    public DigitalTokenBean(String token, String clientNonce, String serverNonce, boolean digitalWallet, int expire) {
        this.id = this.id;
        this.token = token;
        this.clientNonce = clientNonce;
        this.serverNonce = serverNonce;
        this.digitalWallet = digitalWallet;
        this.expire = expire;
    }

    public DigitalTokenBean(int id, String token, String clientNonce, String serverNonce, boolean digitalWallet, int expire) {
        this.id = id;
        this.token = token;
        this.clientNonce = clientNonce;
        this.serverNonce = serverNonce;
        this.digitalWallet = digitalWallet;
        this.expire = expire;
    }

    protected DigitalTokenBean(Parcel in) {
        this.id = in.readInt();
        this.token = in.readString();
        this.clientNonce = in.readString();
        this.serverNonce = in.readString();
        this.digitalWallet = in.readByte() != 0;
        this.expire = in.readInt();
    }

    public int getId() {
        return this.id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getToken() {
        return this.token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getClientNonce() {
        return this.clientNonce;
    }

    public void setClientNonce(String clientNonce) {
        this.clientNonce = clientNonce;
    }

    public String getServerNonce() {
        return this.serverNonce;
    }

    public void setServerNonce(String serverNonce) {
        this.serverNonce = serverNonce;
    }

    public boolean isDigitalWallet() {
        return this.digitalWallet;
    }

    public void setDigitalWallet(boolean digitalWallet) {
        this.digitalWallet = digitalWallet;
    }

    public int getExpire() {
        return this.expire;
    }

    public void setExpire(int expire) {
        this.expire = expire;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeInt(this.id);
        parcel.writeString(this.token);
        parcel.writeString(this.clientNonce);
        parcel.writeString(this.serverNonce);
        parcel.writeByte(this.digitalWallet ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.expire);
    }

    public String toString() {
        return "DigitalTokenBean{id='" + this.id + "'token='" + this.token + "', clientNonce='" + this.clientNonce + "', serverNonce='" + this.serverNonce + "', digitalWallet='" + this.digitalWallet + "', expire=" + this.expire + '}';
    }
}
