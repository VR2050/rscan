package com.google.android.gms.internal.vision;

import java.util.Arrays;
import java.util.Collection;
import java.util.RandomAccess;

/* JADX INFO: loaded from: classes.dex */
final class zzbm extends zzbi<Boolean> implements zzcw<Boolean>, zzej, RandomAccess {
    private static final zzbm zzgr;
    private int size;
    private boolean[] zzgs;

    static {
        zzbm zzbmVar = new zzbm();
        zzgr = zzbmVar;
        zzbmVar.zzao();
    }

    zzbm() {
        this(new boolean[10], 0);
    }

    private zzbm(boolean[] zArr, int i) {
        this.zzgs = zArr;
        this.size = i;
    }

    private final void zza(int i, boolean z) {
        int i2;
        zzap();
        if (i < 0 || i > (i2 = this.size)) {
            throw new IndexOutOfBoundsException(zzj(i));
        }
        boolean[] zArr = this.zzgs;
        if (i2 < zArr.length) {
            System.arraycopy(zArr, i, zArr, i + 1, i2 - i);
        } else {
            boolean[] zArr2 = new boolean[((i2 * 3) / 2) + 1];
            System.arraycopy(zArr, 0, zArr2, 0, i);
            System.arraycopy(this.zzgs, i, zArr2, i + 1, this.size - i);
            this.zzgs = zArr2;
        }
        this.zzgs[i] = z;
        this.size++;
        this.modCount++;
    }

    private final void zzi(int i) {
        if (i < 0 || i >= this.size) {
            throw new IndexOutOfBoundsException(zzj(i));
        }
    }

    private final String zzj(int i) {
        int i2 = this.size;
        StringBuilder sb = new StringBuilder(35);
        sb.append("Index:");
        sb.append(i);
        sb.append(", Size:");
        sb.append(i2);
        return sb.toString();
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final /* synthetic */ void add(int i, Object obj) {
        zza(i, ((Boolean) obj).booleanValue());
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection<? extends Boolean> collection) {
        zzap();
        zzct.checkNotNull(collection);
        if (!(collection instanceof zzbm)) {
            return super.addAll(collection);
        }
        zzbm zzbmVar = (zzbm) collection;
        int i = zzbmVar.size;
        if (i == 0) {
            return false;
        }
        int i2 = this.size;
        if (Integer.MAX_VALUE - i2 < i) {
            throw new OutOfMemoryError();
        }
        int i3 = i2 + i;
        boolean[] zArr = this.zzgs;
        if (i3 > zArr.length) {
            this.zzgs = Arrays.copyOf(zArr, i3);
        }
        System.arraycopy(zzbmVar.zzgs, 0, this.zzgs, this.size, zzbmVar.size);
        this.size = i3;
        this.modCount++;
        return true;
    }

    public final void addBoolean(boolean z) {
        zza(this.size, z);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.Collection, java.util.List
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof zzbm)) {
            return super.equals(obj);
        }
        zzbm zzbmVar = (zzbm) obj;
        if (this.size != zzbmVar.size) {
            return false;
        }
        boolean[] zArr = zzbmVar.zzgs;
        for (int i = 0; i < this.size; i++) {
            if (this.zzgs[i] != zArr[i]) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.AbstractList, java.util.List
    public final /* synthetic */ Object get(int i) {
        zzi(i);
        return Boolean.valueOf(this.zzgs[i]);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.Collection, java.util.List
    public final int hashCode() {
        int iZzc = 1;
        for (int i = 0; i < this.size; i++) {
            iZzc = (iZzc * 31) + zzct.zzc(this.zzgs[i]);
        }
        return iZzc;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final /* synthetic */ Object remove(int i) {
        zzap();
        zzi(i);
        boolean[] zArr = this.zzgs;
        boolean z = zArr[i];
        int i2 = this.size;
        if (i < i2 - 1) {
            System.arraycopy(zArr, i + 1, zArr, i, i2 - i);
        }
        this.size--;
        this.modCount++;
        return Boolean.valueOf(z);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean remove(Object obj) {
        zzap();
        for (int i = 0; i < this.size; i++) {
            if (obj.equals(Boolean.valueOf(this.zzgs[i]))) {
                boolean[] zArr = this.zzgs;
                System.arraycopy(zArr, i + 1, zArr, i, this.size - i);
                this.size--;
                this.modCount++;
                return true;
            }
        }
        return false;
    }

    @Override // java.util.AbstractList
    protected final void removeRange(int i, int i2) {
        zzap();
        if (i2 < i) {
            throw new IndexOutOfBoundsException("toIndex < fromIndex");
        }
        boolean[] zArr = this.zzgs;
        System.arraycopy(zArr, i2, zArr, i, this.size - i2);
        this.size -= i2 - i;
        this.modCount++;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final /* synthetic */ Object set(int i, Object obj) {
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        zzap();
        zzi(i);
        boolean[] zArr = this.zzgs;
        boolean z = zArr[i];
        zArr[i] = zBooleanValue;
        return Boolean.valueOf(z);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.size;
    }

    @Override // com.google.android.gms.internal.vision.zzcw
    public final /* synthetic */ zzcw<Boolean> zzk(int i) {
        if (i >= this.size) {
            return new zzbm(Arrays.copyOf(this.zzgs, i), this.size);
        }
        throw new IllegalArgumentException();
    }
}
