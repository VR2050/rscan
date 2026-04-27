package com.google.android.gms.internal.vision;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/* JADX INFO: loaded from: classes.dex */
final class zzek {
    private static final zzek zznx = new zzek();
    private final zzeo zzny;
    private final ConcurrentMap<Class<?>, zzen<?>> zznz = new ConcurrentHashMap();

    private zzek() {
        String[] strArr = {"com.google.protobuf.AndroidProto3SchemaFactory"};
        zzeo zzeoVarZzk = null;
        for (int i = 0; i <= 0; i++) {
            zzeoVarZzk = zzk(strArr[0]);
            if (zzeoVarZzk != null) {
                break;
            }
        }
        this.zzny = zzeoVarZzk == null ? new zzdm() : zzeoVarZzk;
    }

    public static zzek zzdc() {
        return zznx;
    }

    private static zzeo zzk(String str) {
        try {
            return (zzeo) Class.forName(str).getConstructor(new Class[0]).newInstance(new Object[0]);
        } catch (Throwable th) {
            return null;
        }
    }

    public final <T> zzen<T> zze(Class<T> cls) {
        zzct.zza(cls, "messageType");
        zzen<T> zzenVar = (zzen) this.zznz.get(cls);
        if (zzenVar != null) {
            return zzenVar;
        }
        zzen<T> zzenVarZzd = this.zzny.zzd(cls);
        zzct.zza(cls, "messageType");
        zzct.zza(zzenVarZzd, "schema");
        zzen<T> zzenVar2 = (zzen) this.zznz.putIfAbsent(cls, zzenVarZzd);
        return zzenVar2 != null ? zzenVar2 : zzenVarZzd;
    }

    public final <T> zzen<T> zzq(T t) {
        return zze(t.getClass());
    }
}
