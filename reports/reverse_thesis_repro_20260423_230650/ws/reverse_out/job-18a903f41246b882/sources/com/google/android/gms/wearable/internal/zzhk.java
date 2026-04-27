package com.google.android.gms.wearable.internal;

import android.content.IntentFilter;
import com.google.android.gms.common.api.internal.ListenerHolder;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.Preconditions;
import com.google.android.gms.wearable.CapabilityApi;
import com.google.android.gms.wearable.ChannelApi;
import com.google.android.gms.wearable.DataApi;
import com.google.android.gms.wearable.MessageApi;
import java.util.List;
import javax.annotation.Nullable;

/* JADX INFO: loaded from: classes.dex */
public final class zzhk<T> extends zzen {
    private final IntentFilter[] zzba;

    @Nullable
    private final String zzbb;
    private ListenerHolder<Object> zzfj;
    private ListenerHolder<Object> zzfk;
    private ListenerHolder<DataApi.DataListener> zzfl;
    private ListenerHolder<MessageApi.MessageListener> zzfm;
    private ListenerHolder<Object> zzfn;
    private ListenerHolder<Object> zzfo;
    private ListenerHolder<ChannelApi.ChannelListener> zzfp;
    private ListenerHolder<CapabilityApi.CapabilityListener> zzfq;

    public static zzhk<DataApi.DataListener> zza(ListenerHolder<DataApi.DataListener> listenerHolder, IntentFilter[] intentFilterArr) {
        zzhk<DataApi.DataListener> zzhkVar = new zzhk<>(intentFilterArr, null);
        ((zzhk) zzhkVar).zzfl = (ListenerHolder) Preconditions.checkNotNull(listenerHolder);
        return zzhkVar;
    }

    public static zzhk<MessageApi.MessageListener> zzb(ListenerHolder<MessageApi.MessageListener> listenerHolder, IntentFilter[] intentFilterArr) {
        zzhk<MessageApi.MessageListener> zzhkVar = new zzhk<>(intentFilterArr, null);
        ((zzhk) zzhkVar).zzfm = (ListenerHolder) Preconditions.checkNotNull(listenerHolder);
        return zzhkVar;
    }

    public static zzhk<ChannelApi.ChannelListener> zzc(ListenerHolder<ChannelApi.ChannelListener> listenerHolder, IntentFilter[] intentFilterArr) {
        zzhk<ChannelApi.ChannelListener> zzhkVar = new zzhk<>(intentFilterArr, null);
        ((zzhk) zzhkVar).zzfp = (ListenerHolder) Preconditions.checkNotNull(listenerHolder);
        return zzhkVar;
    }

    public static zzhk<ChannelApi.ChannelListener> zza(ListenerHolder<ChannelApi.ChannelListener> listenerHolder, String str, IntentFilter[] intentFilterArr) {
        zzhk<ChannelApi.ChannelListener> zzhkVar = new zzhk<>(intentFilterArr, (String) Preconditions.checkNotNull(str));
        ((zzhk) zzhkVar).zzfp = (ListenerHolder) Preconditions.checkNotNull(listenerHolder);
        return zzhkVar;
    }

    public static zzhk<CapabilityApi.CapabilityListener> zzd(ListenerHolder<CapabilityApi.CapabilityListener> listenerHolder, IntentFilter[] intentFilterArr) {
        zzhk<CapabilityApi.CapabilityListener> zzhkVar = new zzhk<>(intentFilterArr, null);
        ((zzhk) zzhkVar).zzfq = (ListenerHolder) Preconditions.checkNotNull(listenerHolder);
        return zzhkVar;
    }

    private zzhk(IntentFilter[] intentFilterArr, @Nullable String str) {
        this.zzba = (IntentFilter[]) Preconditions.checkNotNull(intentFilterArr);
        this.zzbb = str;
    }

    public final void clear() {
        zza((ListenerHolder<?>) null);
        this.zzfj = null;
        zza((ListenerHolder<?>) null);
        this.zzfk = null;
        zza(this.zzfl);
        this.zzfl = null;
        zza(this.zzfm);
        this.zzfm = null;
        zza((ListenerHolder<?>) null);
        this.zzfn = null;
        zza((ListenerHolder<?>) null);
        this.zzfo = null;
        zza(this.zzfp);
        this.zzfp = null;
        zza(this.zzfq);
        this.zzfq = null;
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzl zzlVar) {
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzi zziVar) {
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(DataHolder dataHolder) {
        ListenerHolder<DataApi.DataListener> listenerHolder = this.zzfl;
        if (listenerHolder != null) {
            listenerHolder.notifyListener(new zzhl(dataHolder));
        } else {
            dataHolder.close();
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzfe zzfeVar) {
        ListenerHolder<MessageApi.MessageListener> listenerHolder = this.zzfm;
        if (listenerHolder != null) {
            listenerHolder.notifyListener(new zzhm(zzfeVar));
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzfo zzfoVar) {
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zzb(zzfo zzfoVar) {
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void onConnectedNodes(List<zzfo> list) {
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzaw zzawVar) {
        ListenerHolder<ChannelApi.ChannelListener> listenerHolder = this.zzfp;
        if (listenerHolder != null) {
            listenerHolder.notifyListener(new zzhn(zzawVar));
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzem
    public final void zza(zzah zzahVar) {
        ListenerHolder<CapabilityApi.CapabilityListener> listenerHolder = this.zzfq;
        if (listenerHolder != null) {
            listenerHolder.notifyListener(new zzho(zzahVar));
        }
    }

    public final IntentFilter[] zze() {
        return this.zzba;
    }

    @Nullable
    public final String zzf() {
        return this.zzbb;
    }

    private static void zza(ListenerHolder<?> listenerHolder) {
        if (listenerHolder != null) {
            listenerHolder.clear();
        }
    }
}
