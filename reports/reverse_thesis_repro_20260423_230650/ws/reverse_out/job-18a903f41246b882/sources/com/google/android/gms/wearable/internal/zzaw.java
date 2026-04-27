package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelWriter;
import com.google.android.gms.wearable.ChannelApi;

/* JADX INFO: loaded from: classes.dex */
public final class zzaw extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzaw> CREATOR = new zzax();
    private final int type;
    private final int zzcj;
    private final zzay zzck;
    private final int zzg;

    public zzaw(zzay zzayVar, int i, int i2, int i3) {
        this.zzck = zzayVar;
        this.type = i;
        this.zzg = i2;
        this.zzcj = i3;
    }

    public final void zza(ChannelApi.ChannelListener channelListener) {
        int i = this.type;
        if (i == 1) {
            channelListener.onChannelOpened(this.zzck);
            return;
        }
        if (i == 2) {
            channelListener.onChannelClosed(this.zzck, this.zzg, this.zzcj);
            return;
        }
        if (i == 3) {
            channelListener.onInputClosed(this.zzck, this.zzg, this.zzcj);
            return;
        }
        if (i == 4) {
            channelListener.onOutputClosed(this.zzck, this.zzg, this.zzcj);
            return;
        }
        StringBuilder sb = new StringBuilder(25);
        sb.append("Unknown type: ");
        sb.append(i);
        Log.w("ChannelEventParcelable", sb.toString());
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iBeginObjectHeader = SafeParcelWriter.beginObjectHeader(parcel);
        SafeParcelWriter.writeParcelable(parcel, 2, this.zzck, i, false);
        SafeParcelWriter.writeInt(parcel, 3, this.type);
        SafeParcelWriter.writeInt(parcel, 4, this.zzg);
        SafeParcelWriter.writeInt(parcel, 5, this.zzcj);
        SafeParcelWriter.finishObjectHeader(parcel, iBeginObjectHeader);
    }

    public final String toString() {
        String string;
        String string2;
        String strValueOf = String.valueOf(this.zzck);
        int i = this.type;
        if (i == 1) {
            string = "CHANNEL_OPENED";
        } else if (i != 2) {
            if (i == 3) {
                string = "INPUT_CLOSED";
            } else if (i == 4) {
                string = "OUTPUT_CLOSED";
            } else {
                string = Integer.toString(i);
            }
        } else {
            string = "CHANNEL_CLOSED";
        }
        int i2 = this.zzg;
        if (i2 == 0) {
            string2 = "CLOSE_REASON_NORMAL";
        } else if (i2 == 1) {
            string2 = "CLOSE_REASON_DISCONNECTED";
        } else if (i2 != 2) {
            if (i2 == 3) {
                string2 = "CLOSE_REASON_LOCAL_CLOSE";
            } else {
                string2 = Integer.toString(i2);
            }
        } else {
            string2 = "CLOSE_REASON_REMOTE_CLOSE";
        }
        int i3 = this.zzcj;
        StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + 81 + String.valueOf(string).length() + String.valueOf(string2).length());
        sb.append("ChannelEventParcelable[, channel=");
        sb.append(strValueOf);
        sb.append(", type=");
        sb.append(string);
        sb.append(", closeReason=");
        sb.append(string2);
        sb.append(", appErrorCode=");
        sb.append(i3);
        sb.append("]");
        return sb.toString();
    }
}
