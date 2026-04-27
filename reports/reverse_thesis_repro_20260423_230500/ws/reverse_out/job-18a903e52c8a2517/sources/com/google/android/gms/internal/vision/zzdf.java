package com.google.android.gms.internal.vision;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.RandomAccess;

/* JADX INFO: loaded from: classes.dex */
public final class zzdf extends zzbi<String> implements zzdg, RandomAccess {
    private static final zzdf zzml;
    private static final zzdg zzmm;
    private final List<Object> zzmn;

    static {
        zzdf zzdfVar = new zzdf();
        zzml = zzdfVar;
        zzdfVar.zzao();
        zzmm = zzml;
    }

    public zzdf() {
        this(10);
    }

    public zzdf(int i) {
        this((ArrayList<Object>) new ArrayList(i));
    }

    private zzdf(ArrayList<Object> arrayList) {
        this.zzmn = arrayList;
    }

    private static String zzf(Object obj) {
        return obj instanceof String ? (String) obj : obj instanceof zzbo ? ((zzbo) obj).zzas() : zzct.zzg((byte[]) obj);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final /* synthetic */ void add(int i, Object obj) {
        zzap();
        this.zzmn.add(i, (String) obj);
        this.modCount++;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final boolean addAll(int i, Collection<? extends String> collection) {
        zzap();
        if (collection instanceof zzdg) {
            collection = ((zzdg) collection).zzck();
        }
        boolean zAddAll = this.zzmn.addAll(i, collection);
        this.modCount++;
        return zAddAll;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean addAll(Collection<? extends String> collection) {
        return addAll(size(), collection);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final void clear() {
        zzap();
        this.zzmn.clear();
        this.modCount++;
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.Collection, java.util.List
    public final /* bridge */ /* synthetic */ boolean equals(Object obj) {
        return super.equals(obj);
    }

    @Override // java.util.AbstractList, java.util.List
    public final /* synthetic */ Object get(int i) {
        Object obj = this.zzmn.get(i);
        if (obj instanceof String) {
            return (String) obj;
        }
        if (obj instanceof zzbo) {
            zzbo zzboVar = (zzbo) obj;
            String strZzas = zzboVar.zzas();
            if (zzboVar.zzat()) {
                this.zzmn.set(i, strZzas);
            }
            return strZzas;
        }
        byte[] bArr = (byte[]) obj;
        String strZzg = zzct.zzg(bArr);
        if (zzct.zzf(bArr)) {
            this.zzmn.set(i, strZzg);
        }
        return strZzg;
    }

    @Override // com.google.android.gms.internal.vision.zzdg
    public final Object getRaw(int i) {
        return this.zzmn.get(i);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.Collection, java.util.List
    public final /* bridge */ /* synthetic */ int hashCode() {
        return super.hashCode();
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final /* synthetic */ Object remove(int i) {
        zzap();
        Object objRemove = this.zzmn.remove(i);
        this.modCount++;
        return zzf(objRemove);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final /* bridge */ /* synthetic */ boolean remove(Object obj) {
        return super.remove(obj);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final /* bridge */ /* synthetic */ boolean removeAll(Collection collection) {
        return super.removeAll(collection);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final /* bridge */ /* synthetic */ boolean retainAll(Collection collection) {
        return super.retainAll(collection);
    }

    @Override // com.google.android.gms.internal.vision.zzbi, java.util.AbstractList, java.util.List
    public final /* synthetic */ Object set(int i, Object obj) {
        zzap();
        return zzf(this.zzmn.set(i, (String) obj));
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.zzmn.size();
    }

    @Override // com.google.android.gms.internal.vision.zzbi, com.google.android.gms.internal.vision.zzcw
    public final /* bridge */ /* synthetic */ boolean zzan() {
        return super.zzan();
    }

    @Override // com.google.android.gms.internal.vision.zzdg
    public final void zzc(zzbo zzboVar) {
        zzap();
        this.zzmn.add(zzboVar);
        this.modCount++;
    }

    @Override // com.google.android.gms.internal.vision.zzdg
    public final List<?> zzck() {
        return Collections.unmodifiableList(this.zzmn);
    }

    @Override // com.google.android.gms.internal.vision.zzdg
    public final zzdg zzcl() {
        return zzan() ? new zzfi(this) : this;
    }

    @Override // com.google.android.gms.internal.vision.zzcw
    public final /* synthetic */ zzcw zzk(int i) {
        if (i < size()) {
            throw new IllegalArgumentException();
        }
        ArrayList arrayList = new ArrayList(i);
        arrayList.addAll(this.zzmn);
        return new zzdf((ArrayList<Object>) arrayList);
    }
}
