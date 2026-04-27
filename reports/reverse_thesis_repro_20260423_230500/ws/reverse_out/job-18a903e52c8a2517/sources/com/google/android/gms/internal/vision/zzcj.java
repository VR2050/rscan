package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzcl;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
final class zzcj<FieldDescriptorType extends zzcl<FieldDescriptorType>> {
    private static final zzcj zzhx = new zzcj(true);
    private boolean zzhv;
    private boolean zzhw = false;
    private final zzeq<FieldDescriptorType, Object> zzhu = zzeq.zzam(16);

    private zzcj() {
    }

    private zzcj(boolean z) {
        zzao();
    }

    static int zza(zzft zzftVar, int i, Object obj) {
        int iZzt = zzca.zzt(i);
        if (zzftVar == zzft.zzqf) {
            zzct.zzf((zzdx) obj);
            iZzt <<= 1;
        }
        return iZzt + zzb(zzftVar, obj);
    }

    private final Object zza(FieldDescriptorType fielddescriptortype) {
        Object obj = this.zzhu.get(fielddescriptortype);
        return obj instanceof zzda ? zzda.zzci() : obj;
    }

    static void zza(zzca zzcaVar, zzft zzftVar, int i, Object obj) throws IOException {
        if (zzftVar == zzft.zzqf) {
            zzdx zzdxVar = (zzdx) obj;
            zzct.zzf(zzdxVar);
            zzcaVar.zzd(i, 3);
            zzdxVar.zzb(zzcaVar);
            zzcaVar.zzd(i, 4);
        }
        zzcaVar.zzd(i, zzftVar.zzee());
        switch (zzck.zzhz[zzftVar.ordinal()]) {
            case 1:
                zzcaVar.zza(((Double) obj).doubleValue());
                break;
            case 2:
                zzcaVar.zzc(((Float) obj).floatValue());
                break;
            case 3:
                zzcaVar.zzb(((Long) obj).longValue());
                break;
            case 4:
                zzcaVar.zzb(((Long) obj).longValue());
                break;
            case 5:
                zzcaVar.zzp(((Integer) obj).intValue());
                break;
            case 6:
                zzcaVar.zzd(((Long) obj).longValue());
                break;
            case 7:
                zzcaVar.zzs(((Integer) obj).intValue());
                break;
            case 8:
                zzcaVar.zza(((Boolean) obj).booleanValue());
                break;
            case 9:
                ((zzdx) obj).zzb(zzcaVar);
                break;
            case 10:
                zzcaVar.zzb((zzdx) obj);
                break;
            case 11:
                if (!(obj instanceof zzbo)) {
                    zzcaVar.zzh((String) obj);
                } else {
                    zzcaVar.zza((zzbo) obj);
                }
                break;
            case 12:
                if (!(obj instanceof zzbo)) {
                    byte[] bArr = (byte[]) obj;
                    zzcaVar.zzd(bArr, 0, bArr.length);
                } else {
                    zzcaVar.zza((zzbo) obj);
                }
                break;
            case 13:
                zzcaVar.zzq(((Integer) obj).intValue());
                break;
            case 14:
                zzcaVar.zzs(((Integer) obj).intValue());
                break;
            case 15:
                zzcaVar.zzd(((Long) obj).longValue());
                break;
            case 16:
                zzcaVar.zzr(((Integer) obj).intValue());
                break;
            case 17:
                zzcaVar.zzc(((Long) obj).longValue());
                break;
            case 18:
                if (!(obj instanceof zzcu)) {
                    zzcaVar.zzp(((Integer) obj).intValue());
                } else {
                    zzcaVar.zzp(((zzcu) obj).zzbn());
                }
                break;
        }
    }

    private final void zza(FieldDescriptorType fielddescriptortype, Object obj) {
        if (!fielddescriptortype.zzbq()) {
            zza(fielddescriptortype.zzbo(), obj);
        } else {
            if (!(obj instanceof List)) {
                throw new IllegalArgumentException("Wrong object type used with protocol message reflection.");
            }
            ArrayList arrayList = new ArrayList();
            arrayList.addAll((List) obj);
            ArrayList arrayList2 = arrayList;
            int size = arrayList2.size();
            int i = 0;
            while (i < size) {
                Object obj2 = arrayList2.get(i);
                i++;
                zza(fielddescriptortype.zzbo(), obj2);
            }
            obj = arrayList;
        }
        if (obj instanceof zzda) {
            this.zzhw = true;
        }
        this.zzhu.put(fielddescriptortype, obj);
    }

    /* JADX WARN: Failed to find 'out' block for switch in B:3:0x0011. Please report as an issue. */
    /* JADX WARN: Removed duplicated region for block: B:10:0x001e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void zza(com.google.android.gms.internal.vision.zzft r2, java.lang.Object r3) {
        /*
            com.google.android.gms.internal.vision.zzct.checkNotNull(r3)
            int[] r0 = com.google.android.gms.internal.vision.zzck.zzhy
            com.google.android.gms.internal.vision.zzfy r2 = r2.zzed()
            int r2 = r2.ordinal()
            r2 = r0[r2]
            r0 = 1
            r1 = 0
            switch(r2) {
                case 1: goto L41;
                case 2: goto L3e;
                case 3: goto L3b;
                case 4: goto L38;
                case 5: goto L35;
                case 6: goto L32;
                case 7: goto L29;
                case 8: goto L20;
                case 9: goto L15;
                default: goto L14;
            }
        L14:
            goto L44
        L15:
            boolean r2 = r3 instanceof com.google.android.gms.internal.vision.zzdx
            if (r2 != 0) goto L43
            boolean r2 = r3 instanceof com.google.android.gms.internal.vision.zzda
            if (r2 == 0) goto L1e
            goto L43
        L1e:
            r0 = 0
            goto L43
        L20:
            boolean r2 = r3 instanceof java.lang.Integer
            if (r2 != 0) goto L43
            boolean r2 = r3 instanceof com.google.android.gms.internal.vision.zzcu
            if (r2 == 0) goto L1e
            goto L43
        L29:
            boolean r2 = r3 instanceof com.google.android.gms.internal.vision.zzbo
            if (r2 != 0) goto L43
            boolean r2 = r3 instanceof byte[]
            if (r2 == 0) goto L1e
            goto L43
        L32:
            boolean r0 = r3 instanceof java.lang.String
            goto L43
        L35:
            boolean r0 = r3 instanceof java.lang.Boolean
            goto L43
        L38:
            boolean r0 = r3 instanceof java.lang.Double
            goto L43
        L3b:
            boolean r0 = r3 instanceof java.lang.Float
            goto L43
        L3e:
            boolean r0 = r3 instanceof java.lang.Long
            goto L43
        L41:
            boolean r0 = r3 instanceof java.lang.Integer
        L43:
            r1 = r0
        L44:
            if (r1 == 0) goto L47
            return
        L47:
            java.lang.IllegalArgumentException r2 = new java.lang.IllegalArgumentException
            java.lang.String r3 = "Wrong object type used with protocol message reflection."
            r2.<init>(r3)
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzcj.zza(com.google.android.gms.internal.vision.zzft, java.lang.Object):void");
    }

    private static int zzb(zzcl<?> zzclVar, Object obj) {
        zzft zzftVarZzbo = zzclVar.zzbo();
        int iZzbn = zzclVar.zzbn();
        if (!zzclVar.zzbq()) {
            return zza(zzftVarZzbo, iZzbn, obj);
        }
        int iZza = 0;
        List list = (List) obj;
        if (zzclVar.zzbr()) {
            Iterator it = list.iterator();
            while (it.hasNext()) {
                iZza += zzb(zzftVarZzbo, it.next());
            }
            return zzca.zzt(iZzbn) + iZza + zzca.zzab(iZza);
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            iZza += zza(zzftVarZzbo, iZzbn, it2.next());
        }
        return iZza;
    }

    private static int zzb(zzft zzftVar, Object obj) {
        switch (zzck.zzhz[zzftVar.ordinal()]) {
            case 1:
                return zzca.zzb(((Double) obj).doubleValue());
            case 2:
                return zzca.zzd(((Float) obj).floatValue());
            case 3:
                return zzca.zze(((Long) obj).longValue());
            case 4:
                return zzca.zzf(((Long) obj).longValue());
            case 5:
                return zzca.zzu(((Integer) obj).intValue());
            case 6:
                return zzca.zzh(((Long) obj).longValue());
            case 7:
                return zzca.zzx(((Integer) obj).intValue());
            case 8:
                return zzca.zzb(((Boolean) obj).booleanValue());
            case 9:
                return zzca.zzd((zzdx) obj);
            case 10:
                return obj instanceof zzda ? zzca.zza((zzda) obj) : zzca.zzc((zzdx) obj);
            case 11:
                return obj instanceof zzbo ? zzca.zzb((zzbo) obj) : zzca.zzi((String) obj);
            case 12:
                return obj instanceof zzbo ? zzca.zzb((zzbo) obj) : zzca.zze((byte[]) obj);
            case 13:
                return zzca.zzv(((Integer) obj).intValue());
            case 14:
                return zzca.zzy(((Integer) obj).intValue());
            case 15:
                return zzca.zzi(((Long) obj).longValue());
            case 16:
                return zzca.zzw(((Integer) obj).intValue());
            case 17:
                return zzca.zzg(((Long) obj).longValue());
            case 18:
                return obj instanceof zzcu ? zzca.zzz(((zzcu) obj).zzbn()) : zzca.zzz(((Integer) obj).intValue());
            default:
                throw new RuntimeException("There is no way to get here, but the compiler thinks otherwise.");
        }
    }

    private static boolean zzb(Map.Entry<FieldDescriptorType, Object> entry) {
        FieldDescriptorType key = entry.getKey();
        if (key.zzbp() == zzfy.MESSAGE) {
            boolean zZzbq = key.zzbq();
            Object value = entry.getValue();
            if (zZzbq) {
                Iterator it = ((List) value).iterator();
                while (it.hasNext()) {
                    if (!((zzdx) it.next()).isInitialized()) {
                        return false;
                    }
                }
            } else {
                if (!(value instanceof zzdx)) {
                    if (value instanceof zzda) {
                        return true;
                    }
                    throw new IllegalArgumentException("Wrong object type used with protocol message reflection.");
                }
                if (!((zzdx) value).isInitialized()) {
                    return false;
                }
            }
        }
        return true;
    }

    public static <T extends zzcl<T>> zzcj<T> zzbk() {
        return zzhx;
    }

    private final void zzc(Map.Entry<FieldDescriptorType, Object> entry) {
        FieldDescriptorType key = entry.getKey();
        Object value = entry.getValue();
        if (value instanceof zzda) {
            value = zzda.zzci();
        }
        if (key.zzbq()) {
            Object objZza = zza(key);
            if (objZza == null) {
                objZza = new ArrayList();
            }
            Iterator it = ((List) value).iterator();
            while (it.hasNext()) {
                ((List) objZza).add(zze(it.next()));
            }
            this.zzhu.put(key, objZza);
            return;
        }
        if (key.zzbp() != zzfy.MESSAGE) {
            this.zzhu.put(key, zze(value));
            return;
        }
        Object objZza2 = zza(key);
        if (objZza2 == null) {
            this.zzhu.put(key, zze(value));
        } else {
            this.zzhu.put(key, objZza2 instanceof zzee ? key.zza((zzee) objZza2, (zzee) value) : key.zza(((zzdx) objZza2).zzbu(), (zzdx) value).zzca());
        }
    }

    private static int zzd(Map.Entry<FieldDescriptorType, Object> entry) {
        FieldDescriptorType key = entry.getKey();
        Object value = entry.getValue();
        if (key.zzbp() != zzfy.MESSAGE || key.zzbq() || key.zzbr()) {
            return zzb((zzcl<?>) key, value);
        }
        boolean z = value instanceof zzda;
        int iZzbn = entry.getKey().zzbn();
        return z ? zzca.zzb(iZzbn, (zzda) value) : zzca.zzb(iZzbn, (zzdx) value);
    }

    private static Object zze(Object obj) {
        if (obj instanceof zzee) {
            return ((zzee) obj).zzcy();
        }
        if (!(obj instanceof byte[])) {
            return obj;
        }
        byte[] bArr = (byte[]) obj;
        byte[] bArr2 = new byte[bArr.length];
        System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
        return bArr2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final /* synthetic */ Object clone() throws CloneNotSupportedException {
        zzcj zzcjVar = new zzcj();
        for (int i = 0; i < this.zzhu.zzdl(); i++) {
            Map.Entry<K, Object> entryZzan = this.zzhu.zzan(i);
            zzcjVar.zza((zzcl) entryZzan.getKey(), entryZzan.getValue());
        }
        Iterator it = this.zzhu.zzdm().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            zzcjVar.zza((zzcl) entry.getKey(), entry.getValue());
        }
        zzcjVar.zzhw = this.zzhw;
        return zzcjVar;
    }

    final Iterator<Map.Entry<FieldDescriptorType, Object>> descendingIterator() {
        return this.zzhw ? new zzdd(this.zzhu.zzdn().iterator()) : this.zzhu.zzdn().iterator();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof zzcj) {
            return this.zzhu.equals(((zzcj) obj).zzhu);
        }
        return false;
    }

    public final int hashCode() {
        return this.zzhu.hashCode();
    }

    final boolean isEmpty() {
        return this.zzhu.isEmpty();
    }

    public final boolean isImmutable() {
        return this.zzhv;
    }

    public final boolean isInitialized() {
        for (int i = 0; i < this.zzhu.zzdl(); i++) {
            if (!zzb(this.zzhu.zzan(i))) {
                return false;
            }
        }
        Iterator it = this.zzhu.zzdm().iterator();
        while (it.hasNext()) {
            if (!zzb((Map.Entry) it.next())) {
                return false;
            }
        }
        return true;
    }

    public final Iterator<Map.Entry<FieldDescriptorType, Object>> iterator() {
        return this.zzhw ? new zzdd(this.zzhu.entrySet().iterator()) : this.zzhu.entrySet().iterator();
    }

    public final void zza(zzcj<FieldDescriptorType> zzcjVar) {
        for (int i = 0; i < zzcjVar.zzhu.zzdl(); i++) {
            zzc(zzcjVar.zzhu.zzan(i));
        }
        Iterator it = zzcjVar.zzhu.zzdm().iterator();
        while (it.hasNext()) {
            zzc((Map.Entry) it.next());
        }
    }

    public final void zzao() {
        if (this.zzhv) {
            return;
        }
        this.zzhu.zzao();
        this.zzhv = true;
    }

    public final int zzbl() {
        int iZzb = 0;
        for (int i = 0; i < this.zzhu.zzdl(); i++) {
            Map.Entry<K, Object> entryZzan = this.zzhu.zzan(i);
            iZzb += zzb((zzcl<?>) entryZzan.getKey(), entryZzan.getValue());
        }
        Iterator it = this.zzhu.zzdm().iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            iZzb += zzb((zzcl<?>) entry.getKey(), entry.getValue());
        }
        return iZzb;
    }

    public final int zzbm() {
        int iZzd = 0;
        for (int i = 0; i < this.zzhu.zzdl(); i++) {
            iZzd += zzd(this.zzhu.zzan(i));
        }
        Iterator it = this.zzhu.zzdm().iterator();
        while (it.hasNext()) {
            iZzd += zzd((Map.Entry) it.next());
        }
        return iZzd;
    }
}
