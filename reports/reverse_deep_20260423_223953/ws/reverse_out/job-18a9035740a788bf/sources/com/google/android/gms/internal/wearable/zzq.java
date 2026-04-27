package com.google.android.gms.internal.wearable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
final class zzq implements Cloneable {
    private Object value;
    private zzo<?, ?> zzhi;
    private List<zzv> zzhj = new ArrayList();

    zzq() {
    }

    final void zza(zzv zzvVar) throws IOException {
        List<zzv> list = this.zzhj;
        if (list != null) {
            list.add(zzvVar);
            return;
        }
        Object obj = this.value;
        if (obj instanceof zzt) {
            byte[] bArr = zzvVar.zzhm;
            zzk zzkVarZza = zzk.zza(bArr, 0, bArr.length);
            int iZzk = zzkVarZza.zzk();
            if (iZzk != bArr.length - zzl.zzi(iZzk)) {
                throw zzs.zzu();
            }
            zzt zztVarZza = ((zzt) this.value).zza(zzkVarZza);
            this.zzhi = this.zzhi;
            this.value = zztVarZza;
            this.zzhj = null;
            return;
        }
        if (obj instanceof zzt[]) {
            Collections.singletonList(zzvVar);
            throw new NoSuchMethodError();
        }
        Collections.singletonList(zzvVar);
        throw new NoSuchMethodError();
    }

    final int zzg() {
        if (this.value != null) {
            throw new NoSuchMethodError();
        }
        int iZzm = 0;
        for (zzv zzvVar : this.zzhj) {
            iZzm += zzl.zzm(zzvVar.tag) + 0 + zzvVar.zzhm.length;
        }
        return iZzm;
    }

    final void zza(zzl zzlVar) throws IOException {
        if (this.value != null) {
            throw new NoSuchMethodError();
        }
        for (zzv zzvVar : this.zzhj) {
            zzlVar.zzl(zzvVar.tag);
            zzlVar.zzc(zzvVar.zzhm);
        }
    }

    public final boolean equals(Object obj) {
        List<zzv> list;
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof zzq)) {
            return false;
        }
        zzq zzqVar = (zzq) obj;
        if (this.value != null && zzqVar.value != null) {
            zzo<?, ?> zzoVar = this.zzhi;
            if (zzoVar != zzqVar.zzhi) {
                return false;
            }
            if (!zzoVar.zzhd.isArray()) {
                return this.value.equals(zzqVar.value);
            }
            Object obj2 = this.value;
            if (obj2 instanceof byte[]) {
                return Arrays.equals((byte[]) obj2, (byte[]) zzqVar.value);
            }
            if (obj2 instanceof int[]) {
                return Arrays.equals((int[]) obj2, (int[]) zzqVar.value);
            }
            if (obj2 instanceof long[]) {
                return Arrays.equals((long[]) obj2, (long[]) zzqVar.value);
            }
            if (obj2 instanceof float[]) {
                return Arrays.equals((float[]) obj2, (float[]) zzqVar.value);
            }
            if (obj2 instanceof double[]) {
                return Arrays.equals((double[]) obj2, (double[]) zzqVar.value);
            }
            if (obj2 instanceof boolean[]) {
                return Arrays.equals((boolean[]) obj2, (boolean[]) zzqVar.value);
            }
            return Arrays.deepEquals((Object[]) obj2, (Object[]) zzqVar.value);
        }
        List<zzv> list2 = this.zzhj;
        if (list2 != null && (list = zzqVar.zzhj) != null) {
            return list2.equals(list);
        }
        try {
            return Arrays.equals(toByteArray(), zzqVar.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public final int hashCode() {
        try {
            return Arrays.hashCode(toByteArray()) + 527;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private final byte[] toByteArray() throws IOException {
        byte[] bArr = new byte[zzg()];
        zza(zzl.zzb(bArr));
        return bArr;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX INFO: renamed from: zzt, reason: merged with bridge method [inline-methods] */
    public final zzq clone() {
        zzq zzqVar = new zzq();
        try {
            zzqVar.zzhi = this.zzhi;
            if (this.zzhj == null) {
                zzqVar.zzhj = null;
            } else {
                zzqVar.zzhj.addAll(this.zzhj);
            }
            if (this.value != null) {
                if (this.value instanceof zzt) {
                    zzqVar.value = (zzt) ((zzt) this.value).clone();
                } else if (this.value instanceof byte[]) {
                    zzqVar.value = ((byte[]) this.value).clone();
                } else {
                    int i = 0;
                    if (this.value instanceof byte[][]) {
                        byte[][] bArr = (byte[][]) this.value;
                        byte[][] bArr2 = new byte[bArr.length][];
                        zzqVar.value = bArr2;
                        while (i < bArr.length) {
                            bArr2[i] = (byte[]) bArr[i].clone();
                            i++;
                        }
                    } else if (this.value instanceof boolean[]) {
                        zzqVar.value = ((boolean[]) this.value).clone();
                    } else if (this.value instanceof int[]) {
                        zzqVar.value = ((int[]) this.value).clone();
                    } else if (this.value instanceof long[]) {
                        zzqVar.value = ((long[]) this.value).clone();
                    } else if (this.value instanceof float[]) {
                        zzqVar.value = ((float[]) this.value).clone();
                    } else if (this.value instanceof double[]) {
                        zzqVar.value = ((double[]) this.value).clone();
                    } else if (this.value instanceof zzt[]) {
                        zzt[] zztVarArr = (zzt[]) this.value;
                        zzt[] zztVarArr2 = new zzt[zztVarArr.length];
                        zzqVar.value = zztVarArr2;
                        while (i < zztVarArr.length) {
                            zztVarArr2[i] = (zzt) zztVarArr[i].clone();
                            i++;
                        }
                    }
                }
            }
            return zzqVar;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}
