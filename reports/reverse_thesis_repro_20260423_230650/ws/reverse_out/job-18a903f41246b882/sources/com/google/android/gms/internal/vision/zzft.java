package com.google.android.gms.internal.vision;

/* JADX WARN: Enum visitor error
jadx.core.utils.exceptions.JadxRuntimeException: Init of enum field 'zzqe' uses external variables
	at jadx.core.dex.visitors.EnumVisitor.createEnumFieldByConstructor(EnumVisitor.java:451)
	at jadx.core.dex.visitors.EnumVisitor.processEnumFieldByField(EnumVisitor.java:372)
	at jadx.core.dex.visitors.EnumVisitor.processEnumFieldByWrappedInsn(EnumVisitor.java:337)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromFilledArray(EnumVisitor.java:322)
	at jadx.core.dex.visitors.EnumVisitor.extractEnumFieldsFromInsn(EnumVisitor.java:262)
	at jadx.core.dex.visitors.EnumVisitor.convertToEnum(EnumVisitor.java:151)
	at jadx.core.dex.visitors.EnumVisitor.visit(EnumVisitor.java:100)
 */
/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX INFO: loaded from: classes.dex */
public class zzft {
    public static final zzft zzpw = new zzft("DOUBLE", 0, zzfy.DOUBLE, 1);
    public static final zzft zzpx = new zzft("FLOAT", 1, zzfy.FLOAT, 5);
    public static final zzft zzpy = new zzft("INT64", 2, zzfy.LONG, 0);
    public static final zzft zzpz = new zzft("UINT64", 3, zzfy.LONG, 0);
    public static final zzft zzqa = new zzft("INT32", 4, zzfy.INT, 0);
    public static final zzft zzqb = new zzft("FIXED64", 5, zzfy.LONG, 1);
    public static final zzft zzqc = new zzft("FIXED32", 6, zzfy.INT, 5);
    public static final zzft zzqd = new zzft("BOOL", 7, zzfy.BOOLEAN, 0);
    public static final zzft zzqe;
    public static final zzft zzqf;
    public static final zzft zzqg;
    public static final zzft zzqh;
    public static final zzft zzqi;
    public static final zzft zzqj;
    public static final zzft zzqk;
    public static final zzft zzql;
    public static final zzft zzqm;
    public static final zzft zzqn;
    private static final /* synthetic */ zzft[] zzqq;
    private final zzfy zzqo;
    private final int zzqp;

    static {
        final int i = 2;
        final int i2 = 3;
        final zzfy zzfyVar = zzfy.STRING;
        final int i3 = 8;
        final String str = "STRING";
        zzqe = new zzft(str, i3, zzfyVar, i) { // from class: com.google.android.gms.internal.vision.zzfu
            {
                int i4 = 8;
                int i5 = 2;
                zzfs zzfsVar = null;
            }
        };
        final zzfy zzfyVar2 = zzfy.MESSAGE;
        final int i4 = 9;
        final String str2 = "GROUP";
        zzqf = new zzft(str2, i4, zzfyVar2, i2) { // from class: com.google.android.gms.internal.vision.zzfv
            {
                int i5 = 9;
                int i6 = 3;
                zzfs zzfsVar = null;
            }
        };
        final zzfy zzfyVar3 = zzfy.MESSAGE;
        final int i5 = 10;
        final String str3 = "MESSAGE";
        zzqg = new zzft(str3, i5, zzfyVar3, i) { // from class: com.google.android.gms.internal.vision.zzfw
            {
                int i6 = 10;
                int i7 = 2;
                zzfs zzfsVar = null;
            }
        };
        final zzfy zzfyVar4 = zzfy.BYTE_STRING;
        final int i6 = 11;
        final String str4 = "BYTES";
        zzqh = new zzft(str4, i6, zzfyVar4, i) { // from class: com.google.android.gms.internal.vision.zzfx
            {
                int i7 = 11;
                int i8 = 2;
                zzfs zzfsVar = null;
            }
        };
        zzqi = new zzft("UINT32", 12, zzfy.INT, 0);
        zzqj = new zzft("ENUM", 13, zzfy.ENUM, 0);
        zzqk = new zzft("SFIXED32", 14, zzfy.INT, 5);
        zzql = new zzft("SFIXED64", 15, zzfy.LONG, 1);
        zzqm = new zzft("SINT32", 16, zzfy.INT, 0);
        zzft zzftVar = new zzft("SINT64", 17, zzfy.LONG, 0);
        zzqn = zzftVar;
        zzqq = new zzft[]{zzpw, zzpx, zzpy, zzpz, zzqa, zzqb, zzqc, zzqd, zzqe, zzqf, zzqg, zzqh, zzqi, zzqj, zzqk, zzql, zzqm, zzftVar};
    }

    private zzft(String str, int i, zzfy zzfyVar, int i2) {
        this.zzqo = zzfyVar;
        this.zzqp = i2;
    }

    /* synthetic */ zzft(String str, int i, zzfy zzfyVar, int i2, zzfs zzfsVar) {
        this(str, i, zzfyVar, i2);
    }

    public static zzft[] values() {
        return (zzft[]) zzqq.clone();
    }

    public final zzfy zzed() {
        return this.zzqo;
    }

    public final int zzee() {
        return this.zzqp;
    }
}
