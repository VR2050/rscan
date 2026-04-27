package com.google.android.gms.internal.vision;

import java.lang.reflect.Field;
import java.nio.Buffer;
import java.security.AccessController;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.misc.Unsafe;

/* JADX INFO: loaded from: classes.dex */
final class zzfl {
    private static final boolean zzhj;
    private static final zzd zzpc;
    private static final boolean zzpd;
    private static final long zzpe;
    private static final long zzpf;
    private static final long zzpg;
    private static final long zzph;
    private static final long zzpi;
    private static final long zzpj;
    private static final long zzpk;
    private static final long zzpl;
    private static final long zzpm;
    private static final long zzpn;
    private static final long zzpo;
    private static final long zzpp;
    private static final long zzpq;
    private static final long zzpr;
    private static final long zzps;
    private static final boolean zzpt;
    private static final Logger logger = Logger.getLogger(zzfl.class.getName());
    private static final Unsafe zznd = zzdz();
    private static final Class<?> zzgm = zzbj.zzar();
    private static final boolean zzpa = zzi(Long.TYPE);
    private static final boolean zzpb = zzi(Integer.TYPE);

    static final class zza extends zzd {
        zza(Unsafe unsafe) {
            super(unsafe);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zza(Object obj, long j, double d) {
            zza(obj, j, Double.doubleToLongBits(d));
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zza(Object obj, long j, float f) {
            zza(obj, j, Float.floatToIntBits(f));
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zza(Object obj, long j, boolean z) {
            if (zzfl.zzpt) {
                zzfl.zzb(obj, j, z);
            } else {
                zzfl.zzc(obj, j, z);
            }
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zze(Object obj, long j, byte b) {
            if (zzfl.zzpt) {
                zzfl.zza(obj, j, b);
            } else {
                zzfl.zzb(obj, j, b);
            }
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final boolean zzl(Object obj, long j) {
            return zzfl.zzpt ? zzfl.zzr(obj, j) : zzfl.zzs(obj, j);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final float zzm(Object obj, long j) {
            return Float.intBitsToFloat(zzj(obj, j));
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final double zzn(Object obj, long j) {
            return Double.longBitsToDouble(zzk(obj, j));
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final byte zzx(Object obj, long j) {
            return zzfl.zzpt ? zzfl.zzp(obj, j) : zzfl.zzq(obj, j);
        }
    }

    static final class zzb extends zzd {
        zzb(Unsafe unsafe) {
            super(unsafe);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zza(Object obj, long j, double d) {
            zza(obj, j, Double.doubleToLongBits(d));
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zza(Object obj, long j, float f) {
            zza(obj, j, Float.floatToIntBits(f));
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zza(Object obj, long j, boolean z) {
            if (zzfl.zzpt) {
                zzfl.zzb(obj, j, z);
            } else {
                zzfl.zzc(obj, j, z);
            }
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zze(Object obj, long j, byte b) {
            if (zzfl.zzpt) {
                zzfl.zza(obj, j, b);
            } else {
                zzfl.zzb(obj, j, b);
            }
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final boolean zzl(Object obj, long j) {
            return zzfl.zzpt ? zzfl.zzr(obj, j) : zzfl.zzs(obj, j);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final float zzm(Object obj, long j) {
            return Float.intBitsToFloat(zzj(obj, j));
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final double zzn(Object obj, long j) {
            return Double.longBitsToDouble(zzk(obj, j));
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final byte zzx(Object obj, long j) {
            return zzfl.zzpt ? zzfl.zzp(obj, j) : zzfl.zzq(obj, j);
        }
    }

    static final class zzc extends zzd {
        zzc(Unsafe unsafe) {
            super(unsafe);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zza(Object obj, long j, double d) {
            this.zzpu.putDouble(obj, j, d);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zza(Object obj, long j, float f) {
            this.zzpu.putFloat(obj, j, f);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zza(Object obj, long j, boolean z) {
            this.zzpu.putBoolean(obj, j, z);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final void zze(Object obj, long j, byte b) {
            this.zzpu.putByte(obj, j, b);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final boolean zzl(Object obj, long j) {
            return this.zzpu.getBoolean(obj, j);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final float zzm(Object obj, long j) {
            return this.zzpu.getFloat(obj, j);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final double zzn(Object obj, long j) {
            return this.zzpu.getDouble(obj, j);
        }

        @Override // com.google.android.gms.internal.vision.zzfl.zzd
        public final byte zzx(Object obj, long j) {
            return this.zzpu.getByte(obj, j);
        }
    }

    static abstract class zzd {
        Unsafe zzpu;

        zzd(Unsafe unsafe) {
            this.zzpu = unsafe;
        }

        public abstract void zza(Object obj, long j, double d);

        public abstract void zza(Object obj, long j, float f);

        public final void zza(Object obj, long j, int i) {
            this.zzpu.putInt(obj, j, i);
        }

        public final void zza(Object obj, long j, long j2) {
            this.zzpu.putLong(obj, j, j2);
        }

        public abstract void zza(Object obj, long j, boolean z);

        public abstract void zze(Object obj, long j, byte b);

        public final int zzj(Object obj, long j) {
            return this.zzpu.getInt(obj, j);
        }

        public final long zzk(Object obj, long j) {
            return this.zzpu.getLong(obj, j);
        }

        public abstract boolean zzl(Object obj, long j);

        public abstract float zzm(Object obj, long j);

        public abstract double zzn(Object obj, long j);

        public abstract byte zzx(Object obj, long j);
    }

    /* JADX WARN: Removed duplicated region for block: B:4:0x0037  */
    static {
        /*
            Method dump skipped, instruction units count: 255
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.vision.zzfl.<clinit>():void");
    }

    private zzfl() {
    }

    static byte zza(byte[] bArr, long j) {
        return zzpc.zzx(bArr, zzpe + j);
    }

    private static long zza(Field field) {
        zzd zzdVar;
        if (field == null || (zzdVar = zzpc) == null) {
            return -1L;
        }
        return zzdVar.zzpu.objectFieldOffset(field);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void zza(Object obj, long j, byte b) {
        long j2 = (-4) & j;
        int iZzj = zzj(obj, j2);
        int i = ((~((int) j)) & 3) << 3;
        zza(obj, j2, ((255 & b) << i) | (iZzj & (~(255 << i))));
    }

    static void zza(Object obj, long j, double d) {
        zzpc.zza(obj, j, d);
    }

    static void zza(Object obj, long j, float f) {
        zzpc.zza(obj, j, f);
    }

    static void zza(Object obj, long j, int i) {
        zzpc.zza(obj, j, i);
    }

    static void zza(Object obj, long j, long j2) {
        zzpc.zza(obj, j, j2);
    }

    static void zza(Object obj, long j, Object obj2) {
        zzpc.zzpu.putObject(obj, j, obj2);
    }

    static void zza(Object obj, long j, boolean z) {
        zzpc.zza(obj, j, z);
    }

    static void zza(byte[] bArr, long j, byte b) {
        zzpc.zze(bArr, zzpe + j, b);
    }

    private static Field zzb(Class<?> cls, String str) {
        try {
            Field declaredField = cls.getDeclaredField(str);
            declaredField.setAccessible(true);
            return declaredField;
        } catch (Throwable th) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void zzb(Object obj, long j, byte b) {
        long j2 = (-4) & j;
        int i = (((int) j) & 3) << 3;
        zza(obj, j2, ((255 & b) << i) | (zzj(obj, j2) & (~(255 << i))));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void zzb(Object obj, long j, boolean z) {
        zza(obj, j, z ? (byte) 1 : (byte) 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void zzc(Object obj, long j, boolean z) {
        zzb(obj, j, z ? (byte) 1 : (byte) 0);
    }

    static boolean zzdx() {
        return zzhj;
    }

    static boolean zzdy() {
        return zzpd;
    }

    static Unsafe zzdz() {
        try {
            return (Unsafe) AccessController.doPrivileged(new zzfm());
        } catch (Throwable th) {
            return null;
        }
    }

    private static boolean zzea() {
        Unsafe unsafe = zznd;
        if (unsafe == null) {
            return false;
        }
        try {
            Class<?> cls = unsafe.getClass();
            cls.getMethod("objectFieldOffset", Field.class);
            cls.getMethod("arrayBaseOffset", Class.class);
            cls.getMethod("arrayIndexScale", Class.class);
            cls.getMethod("getInt", Object.class, Long.TYPE);
            cls.getMethod("putInt", Object.class, Long.TYPE, Integer.TYPE);
            cls.getMethod("getLong", Object.class, Long.TYPE);
            cls.getMethod("putLong", Object.class, Long.TYPE, Long.TYPE);
            cls.getMethod("getObject", Object.class, Long.TYPE);
            cls.getMethod("putObject", Object.class, Long.TYPE, Object.class);
            if (zzbj.zzaq()) {
                return true;
            }
            cls.getMethod("getByte", Object.class, Long.TYPE);
            cls.getMethod("putByte", Object.class, Long.TYPE, Byte.TYPE);
            cls.getMethod("getBoolean", Object.class, Long.TYPE);
            cls.getMethod("putBoolean", Object.class, Long.TYPE, Boolean.TYPE);
            cls.getMethod("getFloat", Object.class, Long.TYPE);
            cls.getMethod("putFloat", Object.class, Long.TYPE, Float.TYPE);
            cls.getMethod("getDouble", Object.class, Long.TYPE);
            cls.getMethod("putDouble", Object.class, Long.TYPE, Double.TYPE);
            return true;
        } catch (Throwable th) {
            Logger logger2 = logger;
            Level level = Level.WARNING;
            String strValueOf = String.valueOf(th);
            StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + 71);
            sb.append("platform method missing - proto runtime falling back to safer methods: ");
            sb.append(strValueOf);
            logger2.logp(level, "com.google.protobuf.UnsafeUtil", "supportsUnsafeArrayOperations", sb.toString());
            return false;
        }
    }

    private static boolean zzeb() {
        Unsafe unsafe = zznd;
        if (unsafe == null) {
            return false;
        }
        try {
            Class<?> cls = unsafe.getClass();
            cls.getMethod("objectFieldOffset", Field.class);
            cls.getMethod("getLong", Object.class, Long.TYPE);
            if (zzec() == null) {
                return false;
            }
            if (zzbj.zzaq()) {
                return true;
            }
            cls.getMethod("getByte", Long.TYPE);
            cls.getMethod("putByte", Long.TYPE, Byte.TYPE);
            cls.getMethod("getInt", Long.TYPE);
            cls.getMethod("putInt", Long.TYPE, Integer.TYPE);
            cls.getMethod("getLong", Long.TYPE);
            cls.getMethod("putLong", Long.TYPE, Long.TYPE);
            cls.getMethod("copyMemory", Long.TYPE, Long.TYPE, Long.TYPE);
            cls.getMethod("copyMemory", Object.class, Long.TYPE, Object.class, Long.TYPE, Long.TYPE);
            return true;
        } catch (Throwable th) {
            Logger logger2 = logger;
            Level level = Level.WARNING;
            String strValueOf = String.valueOf(th);
            StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + 71);
            sb.append("platform method missing - proto runtime falling back to safer methods: ");
            sb.append(strValueOf);
            logger2.logp(level, "com.google.protobuf.UnsafeUtil", "supportsUnsafeByteBufferOperations", sb.toString());
            return false;
        }
    }

    private static Field zzec() {
        Field fieldZzb;
        if (zzbj.zzaq() && (fieldZzb = zzb(Buffer.class, "effectiveDirectAddress")) != null) {
            return fieldZzb;
        }
        Field fieldZzb2 = zzb(Buffer.class, "address");
        if (fieldZzb2 == null || fieldZzb2.getType() != Long.TYPE) {
            return null;
        }
        return fieldZzb2;
    }

    private static int zzg(Class<?> cls) {
        if (zzhj) {
            return zzpc.zzpu.arrayBaseOffset(cls);
        }
        return -1;
    }

    private static int zzh(Class<?> cls) {
        if (zzhj) {
            return zzpc.zzpu.arrayIndexScale(cls);
        }
        return -1;
    }

    private static boolean zzi(Class<?> cls) {
        if (!zzbj.zzaq()) {
            return false;
        }
        try {
            Class<?> cls2 = zzgm;
            cls2.getMethod("peekLong", cls, Boolean.TYPE);
            cls2.getMethod("pokeLong", cls, Long.TYPE, Boolean.TYPE);
            cls2.getMethod("pokeInt", cls, Integer.TYPE, Boolean.TYPE);
            cls2.getMethod("peekInt", cls, Boolean.TYPE);
            cls2.getMethod("pokeByte", cls, Byte.TYPE);
            cls2.getMethod("peekByte", cls);
            cls2.getMethod("pokeByteArray", cls, byte[].class, Integer.TYPE, Integer.TYPE);
            cls2.getMethod("peekByteArray", cls, byte[].class, Integer.TYPE, Integer.TYPE);
            return true;
        } catch (Throwable th) {
            return false;
        }
    }

    static int zzj(Object obj, long j) {
        return zzpc.zzj(obj, j);
    }

    static long zzk(Object obj, long j) {
        return zzpc.zzk(obj, j);
    }

    static boolean zzl(Object obj, long j) {
        return zzpc.zzl(obj, j);
    }

    static float zzm(Object obj, long j) {
        return zzpc.zzm(obj, j);
    }

    static double zzn(Object obj, long j) {
        return zzpc.zzn(obj, j);
    }

    static Object zzo(Object obj, long j) {
        return zzpc.zzpu.getObject(obj, j);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte zzp(Object obj, long j) {
        return (byte) (zzj(obj, (-4) & j) >>> ((int) (((~j) & 3) << 3)));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static byte zzq(Object obj, long j) {
        return (byte) (zzj(obj, (-4) & j) >>> ((int) ((j & 3) << 3)));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean zzr(Object obj, long j) {
        return zzp(obj, j) != 0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean zzs(Object obj, long j) {
        return zzq(obj, j) != 0;
    }
}
