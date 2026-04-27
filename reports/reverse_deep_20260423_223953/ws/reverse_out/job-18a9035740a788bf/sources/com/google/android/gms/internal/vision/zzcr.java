package com.google.android.gms.internal.vision;

import com.google.android.gms.internal.vision.zzcr;
import com.google.android.gms.internal.vision.zzcr.zza;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* JADX INFO: loaded from: classes.dex */
public abstract class zzcr<MessageType extends zzcr<MessageType, BuilderType>, BuilderType extends zza<MessageType, BuilderType>> extends zzbf<MessageType, BuilderType> {
    private static Map<Object, zzcr<?, ?>> zzkt = new ConcurrentHashMap();
    protected zzfg zzkr = zzfg.zzdu();
    private int zzks = -1;

    public static abstract class zza<MessageType extends zzcr<MessageType, BuilderType>, BuilderType extends zza<MessageType, BuilderType>> extends zzbg<MessageType, BuilderType> {
        private final MessageType zzku;
        protected MessageType zzkv;
        private boolean zzkw = false;

        protected zza(MessageType messagetype) {
            this.zzku = messagetype;
            this.zzkv = (MessageType) messagetype.zza(zzd.zzlb, null, null);
        }

        private static void zza(MessageType messagetype, MessageType messagetype2) {
            zzek.zzdc().zzq(messagetype).zzc(messagetype, messagetype2);
        }

        @Override // com.google.android.gms.internal.vision.zzbg
        public /* synthetic */ Object clone() throws CloneNotSupportedException {
            zza zzaVar = (zza) this.zzku.zza(zzd.zzlc, null, null);
            if (!this.zzkw) {
                MessageType messagetype = this.zzkv;
                zzek.zzdc().zzq(messagetype).zzd(messagetype);
                this.zzkw = true;
            }
            zzaVar.zza((zzcr) this.zzkv);
            return zzaVar;
        }

        @Override // com.google.android.gms.internal.vision.zzdz
        public final boolean isInitialized() {
            return zzcr.zza(this.zzkv, false);
        }

        @Override // com.google.android.gms.internal.vision.zzbg
        public final BuilderType zza(MessageType messagetype) {
            zzbx();
            zza(this.zzkv, messagetype);
            return this;
        }

        @Override // com.google.android.gms.internal.vision.zzbg
        /* JADX INFO: renamed from: zzam */
        public final /* synthetic */ zzbg clone() {
            return (zza) clone();
        }

        @Override // com.google.android.gms.internal.vision.zzdz
        public final /* synthetic */ zzdx zzbw() {
            return this.zzku;
        }

        protected final void zzbx() {
            if (this.zzkw) {
                MessageType messagetype = (MessageType) this.zzkv.zza(zzd.zzlb, null, null);
                zza(messagetype, this.zzkv);
                this.zzkv = messagetype;
                this.zzkw = false;
            }
        }

        public final MessageType zzby() {
            boolean zZzp = true;
            if (!this.zzkw) {
                MessageType messagetype = this.zzkv;
                zzek.zzdc().zzq(messagetype).zzd(messagetype);
                this.zzkw = true;
            }
            MessageType messagetype2 = this.zzkv;
            boolean zBooleanValue = Boolean.TRUE.booleanValue();
            byte bByteValue = ((Byte) messagetype2.zza(zzd.zzky, null, null)).byteValue();
            if (bByteValue != 1) {
                if (bByteValue == 0) {
                    zZzp = false;
                } else {
                    zZzp = zzek.zzdc().zzq(messagetype2).zzp(messagetype2);
                    if (zBooleanValue) {
                        messagetype2.zza(zzd.zzkz, zZzp ? messagetype2 : null, null);
                    }
                }
            }
            if (zZzp) {
                return messagetype2;
            }
            throw new zzfe(messagetype2);
        }

        @Override // com.google.android.gms.internal.vision.zzdy
        public final /* synthetic */ zzdx zzbz() {
            if (this.zzkw) {
                return this.zzkv;
            }
            MessageType messagetype = this.zzkv;
            zzek.zzdc().zzq(messagetype).zzd(messagetype);
            this.zzkw = true;
            return this.zzkv;
        }

        @Override // com.google.android.gms.internal.vision.zzdy
        public final /* synthetic */ zzdx zzca() {
            boolean zZzp = true;
            if (!this.zzkw) {
                MessageType messagetype = this.zzkv;
                zzek.zzdc().zzq(messagetype).zzd(messagetype);
                this.zzkw = true;
            }
            MessageType messagetype2 = this.zzkv;
            boolean zBooleanValue = Boolean.TRUE.booleanValue();
            byte bByteValue = ((Byte) messagetype2.zza(zzd.zzky, null, null)).byteValue();
            if (bByteValue != 1) {
                if (bByteValue == 0) {
                    zZzp = false;
                } else {
                    zZzp = zzek.zzdc().zzq(messagetype2).zzp(messagetype2);
                    if (zBooleanValue) {
                        messagetype2.zza(zzd.zzkz, zZzp ? messagetype2 : null, null);
                    }
                }
            }
            if (zZzp) {
                return messagetype2;
            }
            throw new zzfe(messagetype2);
        }
    }

    public static class zzb<T extends zzcr<T, ?>> extends zzbh<T> {
        private T zzku;

        public zzb(T t) {
            this.zzku = t;
        }
    }

    public static abstract class zzc<MessageType extends zzc<MessageType, BuilderType>, BuilderType> extends zzcr<MessageType, BuilderType> implements zzdz {
        protected zzcj<Object> zzkx = zzcj.zzbk();
    }

    public enum zzd {
        public static final int zzky = 1;
        public static final int zzkz = 2;
        public static final int zzla = 3;
        public static final int zzlb = 4;
        public static final int zzlc = 5;
        public static final int zzld = 6;
        public static final int zzle = 7;
        private static final /* synthetic */ int[] zzlf = {1, 2, 3, 4, 5, 6, 7};
        public static final int zzlg = 1;
        public static final int zzlh = 2;
        private static final /* synthetic */ int[] zzli = {1, 2};
        public static final int zzlj = 1;
        public static final int zzlk = 2;
        private static final /* synthetic */ int[] zzll = {1, 2};

        public static int[] values$50KLMJ33DTMIUPRFDTJMOP9FE1P6UT3FC9QMCBQ7CLN6ASJ1EHIM8JB5EDPM2PR59HKN8P949LIN8Q3FCHA6UIBEEPNMMP9R0() {
            return (int[]) zzlf.clone();
        }
    }

    private static <T extends zzcr<T, ?>> T zza(T t, byte[] bArr) throws zzcx {
        T t2 = (T) t.zza(zzd.zzlb, null, null);
        try {
            zzek.zzdc().zzq(t2).zza(t2, bArr, 0, bArr.length, new zzbl());
            zzek.zzdc().zzq(t2).zzd(t2);
            if (t2.zzgi == 0) {
                return t2;
            }
            throw new RuntimeException();
        } catch (IOException e) {
            if (e.getCause() instanceof zzcx) {
                throw ((zzcx) e.getCause());
            }
            throw new zzcx(e.getMessage()).zzg(t2);
        } catch (IndexOutOfBoundsException e2) {
            throw zzcx.zzcb().zzg(t2);
        }
    }

    protected static Object zza(zzdx zzdxVar, String str, Object[] objArr) {
        return new zzem(zzdxVar, str, objArr);
    }

    static Object zza(Method method, Object obj, Object... objArr) {
        try {
            return method.invoke(obj, objArr);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Couldn't use Java reflection to implement protocol message reflection.", e);
        } catch (InvocationTargetException e2) {
            Throwable cause = e2.getCause();
            if (cause instanceof RuntimeException) {
                throw ((RuntimeException) cause);
            }
            if (cause instanceof Error) {
                throw ((Error) cause);
            }
            throw new RuntimeException("Unexpected exception thrown by generated accessor method.", cause);
        }
    }

    protected static <T extends zzcr<?, ?>> void zza(Class<T> cls, T t) {
        zzkt.put(cls, t);
    }

    protected static final <T extends zzcr<T, ?>> boolean zza(T t, boolean z) {
        byte bByteValue = ((Byte) t.zza(zzd.zzky, null, null)).byteValue();
        if (bByteValue == 1) {
            return true;
        }
        if (bByteValue == 0) {
            return false;
        }
        return zzek.zzdc().zzq(t).zzp(t);
    }

    protected static <T extends zzcr<T, ?>> T zzb(T t, byte[] bArr) throws zzcx {
        zzc zzcVar = (T) zza(t, bArr);
        if (zzcVar != null) {
            boolean zBooleanValue = Boolean.TRUE.booleanValue();
            byte bByteValue = ((Byte) zzcVar.zza(zzd.zzky, (Object) null, (Object) null)).byteValue();
            boolean zZzp = true;
            if (bByteValue != 1) {
                if (bByteValue == 0) {
                    zZzp = false;
                } else {
                    zZzp = zzek.zzdc().zzq(zzcVar).zzp(zzcVar);
                    if (zBooleanValue) {
                        zzcVar.zza(zzd.zzkz, zZzp ? zzcVar : null, (Object) null);
                    }
                }
            }
            if (!zZzp) {
                throw new zzcx(new zzfe(zzcVar).getMessage()).zzg(zzcVar);
            }
        }
        return zzcVar;
    }

    protected static <E> zzcw<E> zzbt() {
        return zzel.zzdd();
    }

    static <T extends zzcr<?, ?>> T zzc(Class<T> cls) {
        T t = (T) zzkt.get(cls);
        if (t == null) {
            try {
                Class.forName(cls.getName(), true, cls.getClassLoader());
                t = (T) zzkt.get(cls);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Class initialization cannot fail.", e);
            }
        }
        if (t != null) {
            return t;
        }
        String strValueOf = String.valueOf(cls.getName());
        throw new IllegalStateException(strValueOf.length() != 0 ? "Unable to get default instance for: ".concat(strValueOf) : new String("Unable to get default instance for: "));
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (((zzcr) zza(zzd.zzld, (Object) null, (Object) null)).getClass().isInstance(obj)) {
            return zzek.zzdc().zzq(this).equals(this, (zzcr) obj);
        }
        return false;
    }

    public int hashCode() {
        if (this.zzgi != 0) {
            return this.zzgi;
        }
        this.zzgi = zzek.zzdc().zzq(this).hashCode(this);
        return this.zzgi;
    }

    @Override // com.google.android.gms.internal.vision.zzdz
    public final boolean isInitialized() {
        boolean zBooleanValue = Boolean.TRUE.booleanValue();
        byte bByteValue = ((Byte) zza(zzd.zzky, (Object) null, (Object) null)).byteValue();
        if (bByteValue == 1) {
            return true;
        }
        if (bByteValue == 0) {
            return false;
        }
        boolean zZzp = zzek.zzdc().zzq(this).zzp(this);
        if (zBooleanValue) {
            zza(zzd.zzkz, zZzp ? this : null, (Object) null);
        }
        return zZzp;
    }

    public String toString() {
        return zzea.zza(this, super.toString());
    }

    protected abstract Object zza(int i, Object obj, Object obj2);

    @Override // com.google.android.gms.internal.vision.zzbf
    final int zzal() {
        return this.zzks;
    }

    @Override // com.google.android.gms.internal.vision.zzdx
    public final void zzb(zzca zzcaVar) throws IOException {
        zzek.zzdc().zze(getClass()).zza(this, zzcc.zza(zzcaVar));
    }

    @Override // com.google.android.gms.internal.vision.zzdx
    public final int zzbl() {
        if (this.zzks == -1) {
            this.zzks = zzek.zzdc().zzq(this).zzn(this);
        }
        return this.zzks;
    }

    @Override // com.google.android.gms.internal.vision.zzdx
    public final /* synthetic */ zzdy zzbu() {
        zza zzaVar = (zza) zza(zzd.zzlc, (Object) null, (Object) null);
        zzaVar.zza(this);
        return zzaVar;
    }

    @Override // com.google.android.gms.internal.vision.zzdx
    public final /* synthetic */ zzdy zzbv() {
        return (zza) zza(zzd.zzlc, (Object) null, (Object) null);
    }

    @Override // com.google.android.gms.internal.vision.zzdz
    public final /* synthetic */ zzdx zzbw() {
        return (zzcr) zza(zzd.zzld, (Object) null, (Object) null);
    }

    @Override // com.google.android.gms.internal.vision.zzbf
    final void zzh(int i) {
        this.zzks = i;
    }
}
