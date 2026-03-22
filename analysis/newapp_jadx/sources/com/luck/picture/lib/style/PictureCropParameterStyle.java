package com.luck.picture.lib.style;

import android.graphics.Color;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.ColorInt;

/* loaded from: classes2.dex */
public class PictureCropParameterStyle implements Parcelable {
    public static final Parcelable.Creator<PictureCropParameterStyle> CREATOR = new Parcelable.Creator<PictureCropParameterStyle>() { // from class: com.luck.picture.lib.style.PictureCropParameterStyle.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public PictureCropParameterStyle createFromParcel(Parcel parcel) {
            return new PictureCropParameterStyle(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public PictureCropParameterStyle[] newArray(int i2) {
            return new PictureCropParameterStyle[i2];
        }
    };

    @ColorInt
    public int cropNavBarColor;

    @ColorInt
    public int cropStatusBarColorPrimaryDark;

    @ColorInt
    public int cropTitleBarBackgroundColor;

    @ColorInt
    public int cropTitleColor;
    public boolean isChangeStatusBarFontColor;

    public PictureCropParameterStyle() {
    }

    public static PictureCropParameterStyle ofDefaultCropStyle() {
        return new PictureCropParameterStyle(Color.parseColor("#393a3e"), Color.parseColor("#393a3e"), Color.parseColor("#393a3e"), Color.parseColor("#FFFFFF"), false);
    }

    public static PictureCropParameterStyle ofNewStyle() {
        return new PictureCropParameterStyle(Color.parseColor("#393a3e"), Color.parseColor("#393a3e"), Color.parseColor("#393a3e"), Color.parseColor("#FFFFFF"), false);
    }

    public static PictureCropParameterStyle ofSelectNumberStyle() {
        return new PictureCropParameterStyle(Color.parseColor("#7D7DFF"), Color.parseColor("#7D7DFF"), Color.parseColor("#FFFFFF"), false);
    }

    public static PictureCropParameterStyle ofSelectTotalStyle() {
        return new PictureCropParameterStyle(Color.parseColor("#FFFFFF"), Color.parseColor("#FFFFFF"), Color.parseColor("#000000"), true);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeByte(this.isChangeStatusBarFontColor ? (byte) 1 : (byte) 0);
        parcel.writeInt(this.cropTitleBarBackgroundColor);
        parcel.writeInt(this.cropStatusBarColorPrimaryDark);
        parcel.writeInt(this.cropTitleColor);
        parcel.writeInt(this.cropNavBarColor);
    }

    public PictureCropParameterStyle(int i2, int i3, int i4, boolean z) {
        this.cropTitleBarBackgroundColor = i2;
        this.cropStatusBarColorPrimaryDark = i3;
        this.cropTitleColor = i4;
        this.isChangeStatusBarFontColor = z;
    }

    public PictureCropParameterStyle(int i2, int i3, int i4, int i5, boolean z) {
        this.cropTitleBarBackgroundColor = i2;
        this.cropNavBarColor = i4;
        this.cropStatusBarColorPrimaryDark = i3;
        this.cropTitleColor = i5;
        this.isChangeStatusBarFontColor = z;
    }

    public PictureCropParameterStyle(Parcel parcel) {
        this.isChangeStatusBarFontColor = parcel.readByte() != 0;
        this.cropTitleBarBackgroundColor = parcel.readInt();
        this.cropStatusBarColorPrimaryDark = parcel.readInt();
        this.cropTitleColor = parcel.readInt();
        this.cropNavBarColor = parcel.readInt();
    }
}
