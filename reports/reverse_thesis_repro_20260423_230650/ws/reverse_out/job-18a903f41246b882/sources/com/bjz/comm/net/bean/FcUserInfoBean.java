package com.bjz.comm.net.bean;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.gson.annotations.SerializedName;
import java.io.Serializable;

/* JADX INFO: loaded from: classes4.dex */
public class FcUserInfoBean implements Parcelable, Serializable {
    public static final Parcelable.Creator<FcUserInfoBean> CREATOR = new Parcelable.Creator<FcUserInfoBean>() { // from class: com.bjz.comm.net.bean.FcUserInfoBean.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public FcUserInfoBean createFromParcel(Parcel in) {
            return new FcUserInfoBean(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public FcUserInfoBean[] newArray(int size) {
            return new FcUserInfoBean[size];
        }
    };
    private static final long serialVersionUID = -5042866721105262380L;

    @SerializedName("access_hash")
    private long accessHash;
    private int birthday;

    @SerializedName("first_name")
    private String firstName;

    @SerializedName("last_name")
    private String lastName;
    private AvatarPhotoBean photo;
    private int sex;

    @SerializedName("user_id")
    private int userId;
    private String username;

    public FcUserInfoBean() {
    }

    protected FcUserInfoBean(Parcel in) {
        this.userId = in.readInt();
        this.accessHash = in.readLong();
        this.firstName = in.readString();
        this.lastName = in.readString();
        this.sex = in.readInt();
        this.username = in.readString();
        this.birthday = in.readInt();
    }

    public int getUserId() {
        return this.userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public long getAccessHash() {
        return this.accessHash;
    }

    public void setAccessHash(long accessHash) {
        this.accessHash = accessHash;
    }

    public String getFirstName() {
        return this.firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return this.lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public int getSex() {
        return this.sex;
    }

    public void setSex(int sex) {
        this.sex = sex;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public int getBirthday() {
        return this.birthday;
    }

    public void setBirthday(int birthday) {
        this.birthday = birthday;
    }

    public AvatarPhotoBean getPhoto() {
        return this.photo;
    }

    public void setPhoto(AvatarPhotoBean photo) {
        this.photo = photo;
    }

    public String toString() {
        return "FcUserInfoBean{userId=" + this.userId + ", accessHash=" + this.accessHash + ", firstName='" + this.firstName + "', lastName='" + this.lastName + "', sex=" + this.sex + ", username='" + this.username + "', birthday=" + this.birthday + ", photo=" + this.photo + '}';
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(this.userId);
        dest.writeLong(this.accessHash);
        dest.writeString(this.firstName);
        dest.writeString(this.lastName);
        dest.writeInt(this.sex);
        dest.writeString(this.username);
        dest.writeInt(this.birthday);
    }
}
