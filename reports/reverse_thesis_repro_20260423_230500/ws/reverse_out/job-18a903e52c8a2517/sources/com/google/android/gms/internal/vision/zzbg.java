package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzbf;
import com.google.android.gms.internal.vision.zzbg;

/* JADX INFO: loaded from: classes.dex */
public abstract class zzbg<MessageType extends zzbf<MessageType, BuilderType>, BuilderType extends zzbg<MessageType, BuilderType>> implements zzdy {
    protected abstract BuilderType zza(MessageType messagetype);

    @Override // com.google.android.gms.internal.vision.zzdy
    public final /* synthetic */ zzdy zza(zzdx zzdxVar) {
        if (zzbw().getClass().isInstance(zzdxVar)) {
            return zza((zzbf) zzdxVar);
        }
        throw new IllegalArgumentException("mergeFrom(MessageLite) can only merge messages of the same type.");
    }

    @Override // 
    /* JADX INFO: renamed from: zzam, reason: merged with bridge method [inline-methods] */
    public abstract BuilderType clone();
}
