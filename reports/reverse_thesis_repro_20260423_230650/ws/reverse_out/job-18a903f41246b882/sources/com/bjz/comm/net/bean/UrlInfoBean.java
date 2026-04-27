package com.bjz.comm.net.bean;

import android.os.Parcel;
import android.os.Parcelable;
import com.bjz.comm.net.utils.HttpUtils;

/* JADX INFO: loaded from: classes4.dex */
public class UrlInfoBean implements Parcelable {
    public static final Parcelable.Creator<UrlInfoBean> CREATOR = new Parcelable.Creator<UrlInfoBean>() { // from class: com.bjz.comm.net.bean.UrlInfoBean.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public UrlInfoBean createFromParcel(Parcel in) {
            return new UrlInfoBean(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public UrlInfoBean[] newArray(int size) {
            return new UrlInfoBean[size];
        }
    };
    private long CreateTime;
    private long ForumID;
    private String Thum;
    private String URL;
    private int URLType;
    private float VideoHeight;
    private float VideoWidth;

    protected UrlInfoBean(Parcel in) {
        this.ForumID = in.readLong();
        this.URL = in.readString();
        this.URLType = in.readInt();
        this.Thum = in.readString();
        this.CreateTime = in.readLong();
        this.VideoHeight = in.readFloat();
        this.VideoWidth = in.readFloat();
    }

    public UrlInfoBean(RespFcAlbumListBean bean) {
        this.ForumID = bean.getMainID();
        this.URL = HttpUtils.getInstance().getDownloadFileUrl() + bean.getName();
        this.URLType = bean.getExt();
        this.Thum = bean.getThum();
        this.CreateTime = bean.getCreateAt();
        this.VideoWidth = bean.getWidth();
        this.VideoHeight = bean.getHeight();
    }

    public UrlInfoBean(long forumID, String URL, int URLType, String thum, long createTime, int videoHeight, int videoWidth) {
        this.ForumID = forumID;
        this.URL = URL;
        this.URLType = URLType;
        this.Thum = thum;
        this.CreateTime = createTime;
        this.VideoHeight = videoHeight;
        this.VideoWidth = videoWidth;
    }

    public long getForumID() {
        return this.ForumID;
    }

    public void setForumID(long forumID) {
        this.ForumID = forumID;
    }

    public String getURL() {
        return this.URL;
    }

    public void setURL(String URL) {
        this.URL = URL;
    }

    public int getURLType() {
        return this.URLType;
    }

    public void setURLType(int URLType) {
        this.URLType = URLType;
    }

    public String getThum() {
        return this.Thum;
    }

    public void setThum(String thum) {
        this.Thum = thum;
    }

    public long getCreateTime() {
        return this.CreateTime;
    }

    public void setCreateTime(long createTime) {
        this.CreateTime = createTime;
    }

    public float getVideoHeight() {
        return this.VideoHeight;
    }

    public void setVideoHeight(float videoHeight) {
        this.VideoHeight = videoHeight;
    }

    public float getVideoWidth() {
        return this.VideoWidth;
    }

    public void setVideoWidth(float videoWidth) {
        this.VideoWidth = videoWidth;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(this.ForumID);
        dest.writeString(this.URL);
        dest.writeInt(this.URLType);
        dest.writeString(this.Thum);
        dest.writeLong(this.CreateTime);
        dest.writeFloat(this.VideoHeight);
        dest.writeFloat(this.VideoWidth);
    }

    public String toString() {
        return "UrlInfoBean{ForumID=" + this.ForumID + ", URL='" + this.URL + "', URLType=" + this.URLType + ", Thum='" + this.Thum + "', CreateTime=" + this.CreateTime + ", VideoHeight=" + this.VideoHeight + ", VideoWidth=" + this.VideoWidth + '}';
    }
}
