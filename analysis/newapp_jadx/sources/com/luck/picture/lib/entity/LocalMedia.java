package com.luck.picture.lib.entity;

import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;

/* loaded from: classes2.dex */
public class LocalMedia implements Parcelable {
    public static final Parcelable.Creator<LocalMedia> CREATOR = new Parcelable.Creator<LocalMedia>() { // from class: com.luck.picture.lib.entity.LocalMedia.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public LocalMedia createFromParcel(Parcel parcel) {
            return new LocalMedia(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public LocalMedia[] newArray(int i2) {
            return new LocalMedia[i2];
        }
    };
    private String androidQToPath;
    private long bucketId;
    private int chooseModel;
    private String compressPath;
    private boolean compressed;
    private String cutPath;
    private long duration;
    private String fileName;
    private int height;

    /* renamed from: id */
    private long f10208id;
    private boolean isChecked;
    private boolean isCut;
    public boolean isLongImage;
    private boolean isMaxSelectEnabledMask;
    private boolean isOriginal;
    public int loadLongImageStatus;
    private String mimeType;
    private int num;
    private int orientation;
    private String originalPath;
    private String parentFolderName;
    private String path;
    public int position;
    private String realPath;
    private long size;
    private int width;

    public LocalMedia() {
        this.orientation = -1;
        this.loadLongImageStatus = -1;
        this.bucketId = -1L;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getAndroidQToPath() {
        return this.androidQToPath;
    }

    public long getBucketId() {
        return this.bucketId;
    }

    public int getChooseModel() {
        return this.chooseModel;
    }

    public String getCompressPath() {
        return this.compressPath;
    }

    public String getCutPath() {
        return this.cutPath;
    }

    public long getDuration() {
        return this.duration;
    }

    public String getFileName() {
        return this.fileName;
    }

    public int getHeight() {
        return this.height;
    }

    public long getId() {
        return this.f10208id;
    }

    public String getMimeType() {
        return TextUtils.isEmpty(this.mimeType) ? "image/jpeg" : this.mimeType;
    }

    public int getNum() {
        return this.num;
    }

    public int getOrientation() {
        return this.orientation;
    }

    public String getOriginalPath() {
        return this.originalPath;
    }

    public String getParentFolderName() {
        return this.parentFolderName;
    }

    public String getPath() {
        return this.path;
    }

    public int getPosition() {
        return this.position;
    }

    public String getRealPath() {
        return this.realPath;
    }

    public long getSize() {
        return this.size;
    }

    public int getWidth() {
        return this.width;
    }

    public boolean isChecked() {
        return this.isChecked;
    }

    public boolean isCompressed() {
        return this.compressed;
    }

    public boolean isCut() {
        return this.isCut;
    }

    public boolean isMaxSelectEnabledMask() {
        return this.isMaxSelectEnabledMask;
    }

    public boolean isOriginal() {
        return this.isOriginal;
    }

    public void setAndroidQToPath(String str) {
        this.androidQToPath = str;
    }

    public void setBucketId(long j2) {
        this.bucketId = j2;
    }

    public void setChecked(boolean z) {
        this.isChecked = z;
    }

    public void setChooseModel(int i2) {
        this.chooseModel = i2;
    }

    public void setCompressPath(String str) {
        this.compressPath = str;
    }

    public void setCompressed(boolean z) {
        this.compressed = z;
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

    public void setFileName(String str) {
        this.fileName = str;
    }

    public void setHeight(int i2) {
        this.height = i2;
    }

    public void setId(long j2) {
        this.f10208id = j2;
    }

    public void setMaxSelectEnabledMask(boolean z) {
        this.isMaxSelectEnabledMask = z;
    }

    public void setMimeType(String str) {
        this.mimeType = str;
    }

    public void setNum(int i2) {
        this.num = i2;
    }

    public void setOrientation(int i2) {
        this.orientation = i2;
    }

    public void setOriginal(boolean z) {
        this.isOriginal = z;
    }

    public void setOriginalPath(String str) {
        this.originalPath = str;
    }

    public void setParentFolderName(String str) {
        this.parentFolderName = str;
    }

    public void setPath(String str) {
        this.path = str;
    }

    public void setPosition(int i2) {
        this.position = i2;
    }

    public void setRealPath(String str) {
        this.realPath = str;
    }

    public void setSize(long j2) {
        this.size = j2;
    }

    public void setWidth(int i2) {
        this.width = i2;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeLong(this.f10208id);
        parcel.writeString(this.path);
        parcel.writeString(this.realPath);
        parcel.writeString(this.originalPath);
        parcel.writeString(this.compressPath);
        parcel.writeString(this.cutPath);
        parcel.writeString(this.androidQToPath);
        parcel.writeLong(this.duration);
        parcel.writeByte(this.isChecked ? (byte) 1 : (byte) 0);
        parcel.writeByte(this.isCut ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.position);
        parcel.writeInt(this.num);
        parcel.writeString(this.mimeType);
        parcel.writeInt(this.chooseModel);
        parcel.writeByte(this.compressed ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.width);
        parcel.writeInt(this.height);
        parcel.writeLong(this.size);
        parcel.writeByte(this.isOriginal ? (byte) 1 : (byte) 0);
        parcel.writeString(this.fileName);
        parcel.writeString(this.parentFolderName);
        parcel.writeInt(this.orientation);
        parcel.writeInt(this.loadLongImageStatus);
        parcel.writeByte(this.isLongImage ? (byte) 1 : (byte) 0);
        parcel.writeLong(this.bucketId);
        parcel.writeByte(this.isMaxSelectEnabledMask ? (byte) 1 : (byte) 0);
    }

    public LocalMedia(String str, long j2, int i2, String str2) {
        this.orientation = -1;
        this.loadLongImageStatus = -1;
        this.bucketId = -1L;
        this.path = str;
        this.duration = j2;
        this.chooseModel = i2;
        this.mimeType = str2;
    }

    public LocalMedia(long j2, String str, String str2, String str3, long j3, int i2, String str4, int i3, int i4, long j4) {
        this.orientation = -1;
        this.loadLongImageStatus = -1;
        this.bucketId = -1L;
        this.f10208id = j2;
        this.path = str;
        this.fileName = str2;
        this.parentFolderName = str3;
        this.duration = j3;
        this.chooseModel = i2;
        this.mimeType = str4;
        this.width = i3;
        this.height = i4;
        this.size = j4;
    }

    public LocalMedia(long j2, String str, String str2, String str3, String str4, long j3, int i2, String str5, int i3, int i4, long j4, long j5) {
        this.orientation = -1;
        this.loadLongImageStatus = -1;
        this.bucketId = -1L;
        this.f10208id = j2;
        this.path = str;
        this.realPath = str2;
        this.fileName = str3;
        this.parentFolderName = str4;
        this.duration = j3;
        this.chooseModel = i2;
        this.mimeType = str5;
        this.width = i3;
        this.height = i4;
        this.size = j4;
        this.bucketId = j5;
    }

    public LocalMedia(String str, long j2, boolean z, int i2, int i3, int i4) {
        this.orientation = -1;
        this.loadLongImageStatus = -1;
        this.bucketId = -1L;
        this.path = str;
        this.duration = j2;
        this.isChecked = z;
        this.position = i2;
        this.num = i3;
        this.chooseModel = i4;
    }

    public LocalMedia(Parcel parcel) {
        this.orientation = -1;
        this.loadLongImageStatus = -1;
        this.bucketId = -1L;
        this.f10208id = parcel.readLong();
        this.path = parcel.readString();
        this.realPath = parcel.readString();
        this.originalPath = parcel.readString();
        this.compressPath = parcel.readString();
        this.cutPath = parcel.readString();
        this.androidQToPath = parcel.readString();
        this.duration = parcel.readLong();
        this.isChecked = parcel.readByte() != 0;
        this.isCut = parcel.readByte() != 0;
        this.position = parcel.readInt();
        this.num = parcel.readInt();
        this.mimeType = parcel.readString();
        this.chooseModel = parcel.readInt();
        this.compressed = parcel.readByte() != 0;
        this.width = parcel.readInt();
        this.height = parcel.readInt();
        this.size = parcel.readLong();
        this.isOriginal = parcel.readByte() != 0;
        this.fileName = parcel.readString();
        this.parentFolderName = parcel.readString();
        this.orientation = parcel.readInt();
        this.loadLongImageStatus = parcel.readInt();
        this.isLongImage = parcel.readByte() != 0;
        this.bucketId = parcel.readLong();
        this.isMaxSelectEnabledMask = parcel.readByte() != 0;
    }
}
