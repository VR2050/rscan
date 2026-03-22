package com.luck.picture.lib.config;

import android.os.Parcel;
import android.os.Parcelable;
import com.yalantis.ucrop.UCrop;

/* loaded from: classes2.dex */
public class UCropOptions extends UCrop.Options implements Parcelable {
    public static final Parcelable.Creator<UCropOptions> CREATOR = new Parcelable.Creator<UCropOptions>() { // from class: com.luck.picture.lib.config.UCropOptions.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public UCropOptions createFromParcel(Parcel parcel) {
            return new UCropOptions(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public UCropOptions[] newArray(int i2) {
            return new UCropOptions[i2];
        }
    };

    public UCropOptions() {
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
    }

    public UCropOptions(Parcel parcel) {
    }
}
