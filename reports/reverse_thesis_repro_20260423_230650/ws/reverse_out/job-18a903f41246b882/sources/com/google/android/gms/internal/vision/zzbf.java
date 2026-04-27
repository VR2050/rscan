package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzbf;
import com.google.android.gms.internal.vision.zzbg;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public abstract class zzbf<MessageType extends zzbf<MessageType, BuilderType>, BuilderType extends zzbg<MessageType, BuilderType>> implements zzdx {
    private static boolean zzgj = false;
    protected int zzgi = 0;

    protected static <T> void zza(Iterable<T> iterable, List<? super T> list) {
        zzct.checkNotNull(iterable);
        if (iterable instanceof zzdg) {
            List<?> listZzck = ((zzdg) iterable).zzck();
            zzdg zzdgVar = (zzdg) list;
            int size = list.size();
            for (Object obj : listZzck) {
                if (obj == null) {
                    int size2 = zzdgVar.size() - size;
                    StringBuilder sb = new StringBuilder(37);
                    sb.append("Element at index ");
                    sb.append(size2);
                    sb.append(" is null.");
                    String string = sb.toString();
                    for (int size3 = zzdgVar.size() - 1; size3 >= size; size3--) {
                        zzdgVar.remove(size3);
                    }
                    throw new NullPointerException(string);
                }
                if (obj instanceof zzbo) {
                    zzdgVar.zzc((zzbo) obj);
                } else {
                    zzdgVar.add((String) obj);
                }
            }
            return;
        }
        if (iterable instanceof zzej) {
            list.addAll((Collection) iterable);
            return;
        }
        if ((list instanceof ArrayList) && (iterable instanceof Collection)) {
            ((ArrayList) list).ensureCapacity(list.size() + ((Collection) iterable).size());
        }
        int size4 = list.size();
        for (T t : iterable) {
            if (t == null) {
                int size5 = list.size() - size4;
                StringBuilder sb2 = new StringBuilder(37);
                sb2.append("Element at index ");
                sb2.append(size5);
                sb2.append(" is null.");
                String string2 = sb2.toString();
                for (int size6 = list.size() - 1; size6 >= size4; size6--) {
                    list.remove(size6);
                }
                throw new NullPointerException(string2);
            }
            list.add(t);
        }
    }

    public final byte[] toByteArray() {
        try {
            byte[] bArr = new byte[zzbl()];
            zzca zzcaVarZzd = zzca.zzd(bArr);
            zzb(zzcaVarZzd);
            zzcaVarZzd.zzba();
            return bArr;
        } catch (IOException e) {
            String name = getClass().getName();
            StringBuilder sb = new StringBuilder(String.valueOf(name).length() + 62 + String.valueOf("byte array").length());
            sb.append("Serializing ");
            sb.append(name);
            sb.append(" to a ");
            sb.append("byte array");
            sb.append(" threw an IOException (should never happen).");
            throw new RuntimeException(sb.toString(), e);
        }
    }

    @Override // com.google.android.gms.internal.vision.zzdx
    public final zzbo zzak() {
        try {
            zzbt zzbtVarZzm = zzbo.zzm(zzbl());
            zzb(zzbtVarZzm.zzax());
            return zzbtVarZzm.zzaw();
        } catch (IOException e) {
            String name = getClass().getName();
            StringBuilder sb = new StringBuilder(String.valueOf(name).length() + 62 + String.valueOf("ByteString").length());
            sb.append("Serializing ");
            sb.append(name);
            sb.append(" to a ");
            sb.append("ByteString");
            sb.append(" threw an IOException (should never happen).");
            throw new RuntimeException(sb.toString(), e);
        }
    }

    int zzal() {
        throw new UnsupportedOperationException();
    }

    void zzh(int i) {
        throw new UnsupportedOperationException();
    }
}
