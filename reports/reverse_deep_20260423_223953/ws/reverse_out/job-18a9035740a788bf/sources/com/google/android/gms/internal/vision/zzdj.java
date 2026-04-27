package com.google.android.gms.internal.vision;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
final class zzdj extends zzdh {
    private static final Class<?> zzmq = Collections.unmodifiableList(Collections.emptyList()).getClass();

    private zzdj() {
        super();
    }

    private static <E> List<E> zzb(Object obj, long j) {
        return (List) zzfl.zzo(obj, j);
    }

    @Override // com.google.android.gms.internal.vision.zzdh
    final void zza(Object obj, long j) {
        Object objUnmodifiableList;
        List list = (List) zzfl.zzo(obj, j);
        if (list instanceof zzdg) {
            objUnmodifiableList = ((zzdg) list).zzcl();
        } else if (zzmq.isAssignableFrom(list.getClass())) {
            return;
        } else {
            objUnmodifiableList = Collections.unmodifiableList(list);
        }
        zzfl.zza(obj, j, objUnmodifiableList);
    }

    @Override // com.google.android.gms.internal.vision.zzdh
    final <E> void zza(Object obj, Object obj2, long j) {
        List list;
        List list2;
        List listZzb = zzb(obj2, j);
        int size = listZzb.size();
        List listZzb2 = zzb(obj, j);
        if (listZzb2.isEmpty()) {
            List zzdfVar = listZzb2 instanceof zzdg ? new zzdf(size) : new ArrayList(size);
            zzfl.zza(obj, j, zzdfVar);
            list2 = zzdfVar;
        } else {
            if (zzmq.isAssignableFrom(listZzb2.getClass())) {
                ArrayList arrayList = new ArrayList(listZzb2.size() + size);
                arrayList.addAll(listZzb2);
                list = arrayList;
            } else {
                boolean z = listZzb2 instanceof zzfi;
                list2 = listZzb2;
                if (z) {
                    zzdf zzdfVar2 = new zzdf(listZzb2.size() + size);
                    zzdfVar2.addAll((zzfi) listZzb2);
                    list = zzdfVar2;
                }
            }
            zzfl.zza(obj, j, list);
            list2 = list;
        }
        int size2 = list2.size();
        int size3 = listZzb.size();
        if (size2 > 0 && size3 > 0) {
            list2.addAll(listZzb);
        }
        if (size2 > 0) {
            listZzb = list2;
        }
        zzfl.zza(obj, j, listZzb);
    }
}
