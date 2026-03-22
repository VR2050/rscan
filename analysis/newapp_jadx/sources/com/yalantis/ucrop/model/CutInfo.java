package com.yalantis.ucrop.model;

import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;

/* loaded from: classes2.dex */
public class CutInfo implements Parcelable {
    public static final Parcelable.Creator<CutInfo> CREATOR = new Parcelable.Creator<CutInfo>() { // from class: com.yalantis.ucrop.model.CutInfo.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public CutInfo createFromParcel(Parcel parcel) {
            return new CutInfo(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public CutInfo[] newArray(int i2) {
            return new CutInfo[i2];
        }
    };
    private String androidQToPath;
    private String cutPath;
    private long duration;
    private Uri httpOutUri;

    /* renamed from: id */
    private long f10920id;
    private int imageHeight;
    private int imageWidth;
    private boolean isCut;
    private String mimeType;
    private int offsetX;
    private int offsetY;
    private String path;
    private String realPath;
    private float resultAspectRatio;

    public CutInfo() {
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getAndroidQToPath() {
        return this.androidQToPath;
    }

    public String getCutPath() {
        return this.cutPath;
    }

    public long getDuration() {
        return this.duration;
    }

    public Uri getHttpOutUri() {
        return this.httpOutUri;
    }

    public long getId() {
        return this.f10920id;
    }

    public int getImageHeight() {
        return this.imageHeight;
    }

    public int getImageWidth() {
        return this.imageWidth;
    }

    public String getMimeType() {
        return this.mimeType;
    }

    public int getOffsetX() {
        return this.offsetX;
    }

    public int getOffsetY() {
        return this.offsetY;
    }

    public String getPath() {
        return this.path;
    }

    public String getRealPath() {
        return this.realPath;
    }

    public float getResultAspectRatio() {
        return this.resultAspectRatio;
    }

    public boolean isCut() {
        return this.isCut;
    }

    public void setAndroidQToPath(String str) {
        this.androidQToPath = str;
    }

    public void setCut(boolean z) {
        this.isCut = z;
    }

    public void setCutPath(String str) {
        this.cutPath = str;
    }

    public void setDuration(long j2) {
        this.duration = j2;
    }

    public void setHttpOutUri(Uri uri) {
        this.httpOutUri = uri;
    }

    public void setId(long j2) {
        this.f10920id = j2;
    }

    public void setImageHeight(int i2) {
        this.imageHeight = i2;
    }

    public void setImageWidth(int i2) {
        this.imageWidth = i2;
    }

    public void setMimeType(String str) {
        this.mimeType = str;
    }

    public void setOffsetX(int i2) {
        this.offsetX = i2;
    }

    public void setOffsetY(int i2) {
        this.offsetY = i2;
    }

    public void setPath(String str) {
        this.path = str;
    }

    public void setRealPath(String str) {
        this.realPath = str;
    }

    public void setResultAspectRatio(float f2) {
        this.resultAspectRatio = f2;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeLong(this.f10920id);
        parcel.writeString(this.path);
        parcel.writeString(this.cutPath);
        parcel.writeString(this.androidQToPath);
        parcel.writeInt(this.offsetX);
        parcel.writeInt(this.offsetY);
        parcel.writeInt(this.imageWidth);
        parcel.writeInt(this.imageHeight);
        parcel.writeByte(this.isCut ? (byte) 1 : (byte) 0);
        parcel.writeString(this.mimeType);
        parcel.writeFloat(this.resultAspectRatio);
        parcel.writeLong(this.duration);
        parcel.writeParcelable(this.httpOutUri, i2);
        parcel.writeString(this.realPath);
    }

    public CutInfo(String str, boolean z) {
        this.path = str;
        this.isCut = z;
    }

    public CutInfo(Parcel parcel) {
        this.f10920id = parcel.readLong();
        this.path = parcel.readString();
        this.cutPath = parcel.readString();
        this.androidQToPath = parcel.readString();
        this.offsetX = parcel.readInt();
        this.offsetY = parcel.readInt();
        this.imageWidth = parcel.readInt();
        this.imageHeight = parcel.readInt();
        this.isCut = parcel.readByte() != 0;
        this.mimeType = parcel.readString();
        this.resultAspectRatio = parcel.readFloat();
        this.duration = parcel.readLong();
        this.httpOutUri = (Uri) parcel.readParcelable(Uri.class.getClassLoader());
        this.realPath = parcel.readString();
    }
}
