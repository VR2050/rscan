package com.google.android.gms.wearable.internal;

import com.google.android.gms.wearable.CapabilityInfo;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
final class zzgk {
    /* JADX INFO: Access modifiers changed from: private */
    public static Map<String, CapabilityInfo> zza(List<zzah> list) {
        HashMap map = new HashMap();
        if (list != null) {
            for (zzah zzahVar : list) {
                map.put(zzahVar.getName(), new zzw(zzahVar));
            }
        }
        return map;
    }
}
