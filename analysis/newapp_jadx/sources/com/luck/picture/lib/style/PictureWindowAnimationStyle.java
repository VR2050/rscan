package com.luck.picture.lib.style;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.AnimRes;
import com.luck.picture.lib.C3979R;

/* loaded from: classes2.dex */
public class PictureWindowAnimationStyle implements Parcelable {
    public static final Parcelable.Creator<PictureWindowAnimationStyle> CREATOR = new Parcelable.Creator<PictureWindowAnimationStyle>() { // from class: com.luck.picture.lib.style.PictureWindowAnimationStyle.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public PictureWindowAnimationStyle createFromParcel(Parcel parcel) {
            return new PictureWindowAnimationStyle(parcel);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // android.os.Parcelable.Creator
        public PictureWindowAnimationStyle[] newArray(int i2) {
            return new PictureWindowAnimationStyle[i2];
        }
    };

    @AnimRes
    public int activityCropEnterAnimation;

    @AnimRes
    public int activityCropExitAnimation;

    @AnimRes
    public int activityEnterAnimation;

    @AnimRes
    public int activityExitAnimation;

    @AnimRes
    public int activityPreviewEnterAnimation;

    @AnimRes
    public int activityPreviewExitAnimation;

    public PictureWindowAnimationStyle() {
    }

    public static PictureWindowAnimationStyle ofCustomWindowAnimationStyle(int i2, int i3) {
        return new PictureWindowAnimationStyle(i2, i3);
    }

    public static PictureWindowAnimationStyle ofDefaultWindowAnimationStyle() {
        return new PictureWindowAnimationStyle(C3979R.anim.picture_anim_enter, C3979R.anim.picture_anim_exit);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public void ofAllAnimation(int i2, int i3) {
        this.activityEnterAnimation = i2;
        this.activityExitAnimation = i3;
        this.activityPreviewEnterAnimation = i2;
        this.activityPreviewExitAnimation = i3;
        this.activityCropEnterAnimation = i2;
        this.activityCropExitAnimation = i3;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int i2) {
        parcel.writeInt(this.activityEnterAnimation);
        parcel.writeInt(this.activityExitAnimation);
        parcel.writeInt(this.activityPreviewEnterAnimation);
        parcel.writeInt(this.activityPreviewExitAnimation);
        parcel.writeInt(this.activityCropEnterAnimation);
        parcel.writeInt(this.activityCropExitAnimation);
    }

    public PictureWindowAnimationStyle(@AnimRes int i2, @AnimRes int i3) {
        this.activityEnterAnimation = i2;
        this.activityExitAnimation = i3;
        this.activityPreviewEnterAnimation = i2;
        this.activityPreviewExitAnimation = i3;
        this.activityCropEnterAnimation = i2;
        this.activityCropExitAnimation = i3;
    }

    public PictureWindowAnimationStyle(@AnimRes int i2, @AnimRes int i3, @AnimRes int i4, @AnimRes int i5) {
        this.activityEnterAnimation = i2;
        this.activityExitAnimation = i3;
        this.activityPreviewEnterAnimation = i4;
        this.activityPreviewExitAnimation = i5;
    }

    public PictureWindowAnimationStyle(Parcel parcel) {
        this.activityEnterAnimation = parcel.readInt();
        this.activityExitAnimation = parcel.readInt();
        this.activityPreviewEnterAnimation = parcel.readInt();
        this.activityPreviewExitAnimation = parcel.readInt();
        this.activityCropEnterAnimation = parcel.readInt();
        this.activityCropExitAnimation = parcel.readInt();
    }
}
