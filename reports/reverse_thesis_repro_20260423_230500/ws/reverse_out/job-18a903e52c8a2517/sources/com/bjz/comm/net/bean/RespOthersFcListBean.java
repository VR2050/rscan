package com.bjz.comm.net.bean;

import android.os.Parcel;
import android.os.Parcelable;
import java.io.Serializable;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
public class RespOthersFcListBean implements Parcelable, Serializable {
    public static final Parcelable.Creator<RespOthersFcListBean> CREATOR = new Parcelable.Creator<RespOthersFcListBean>() { // from class: com.bjz.comm.net.bean.RespOthersFcListBean.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public RespOthersFcListBean createFromParcel(Parcel in) {
            return new RespOthersFcListBean(in);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public RespOthersFcListBean[] newArray(int size) {
            return new RespOthersFcListBean[size];
        }
    };
    private static final long serialVersionUID = -8486142001897485591L;
    private boolean Finish;
    private ArrayList<RespFcListBean> Forums;
    private long LastForumID;

    protected RespOthersFcListBean(Parcel in) {
        this.Forums = in.createTypedArrayList(RespFcListBean.CREATOR);
        this.LastForumID = in.readLong();
        this.Finish = in.readByte() != 0;
    }

    public ArrayList<RespFcListBean> getForums() {
        return this.Forums;
    }

    public void setForums(ArrayList<RespFcListBean> forums) {
        this.Forums = forums;
    }

    public long getLastForumID() {
        return this.LastForumID;
    }

    public void setLastForumID(long lastForumID) {
        this.LastForumID = lastForumID;
    }

    public boolean isFinish() {
        return this.Finish;
    }

    public void setFinish(boolean finish) {
        this.Finish = finish;
    }

    public String toString() {
        return "RespOthersFcListBean{Forums=" + this.Forums + ", Finish=" + this.Finish + ", LastForumID=" + this.LastForumID + '}';
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i) {
        parcel.writeTypedList(this.Forums);
        parcel.writeLong(this.LastForumID);
        parcel.writeByte(this.Finish ? (byte) 1 : (byte) 0);
    }
}
