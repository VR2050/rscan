package com.google.android.gms.internal.clearcut;

/* JADX WARN: Enum visitor error
jadx.core.utils.exceptions.JadxRuntimeException: Init of enum field 'zzqk' uses external variables
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
public class zzfl {
    public static final zzfl zzqc = new zzfl("DOUBLE", 0, zzfq.DOUBLE, 1);
    public static final zzfl zzqd = new zzfl("FLOAT", 1, zzfq.FLOAT, 5);
    public static final zzfl zzqe = new zzfl("INT64", 2, zzfq.LONG, 0);
    public static final zzfl zzqf = new zzfl("UINT64", 3, zzfq.LONG, 0);
    public static final zzfl zzqg = new zzfl("INT32", 4, zzfq.INT, 0);
    public static final zzfl zzqh = new zzfl("FIXED64", 5, zzfq.LONG, 1);
    public static final zzfl zzqi = new zzfl("FIXED32", 6, zzfq.INT, 5);
    public static final zzfl zzqj = new zzfl("BOOL", 7, zzfq.BOOLEAN, 0);
    public static final zzfl zzqk;
    public static final zzfl zzql;
    public static final zzfl zzqm;
    public static final zzfl zzqn;
    public static final zzfl zzqo;
    public static final zzfl zzqp;
    public static final zzfl zzqq;
    public static final zzfl zzqr;
    public static final zzfl zzqs;
    public static final zzfl zzqt;
    private static final /* synthetic */ zzfl[] zzqw;
    private final zzfq zzqu;
    private final int zzqv;

    static {
        final int i = 2;
        final int i2 = 3;
        final zzfq zzfqVar = zzfq.STRING;
        final int i3 = 8;
        final String str = "STRING";
        zzqk = new zzfl(str, i3, zzfqVar, i) { // from class: com.google.android.gms.internal.clearcut.zzfm
            {
                int i4 = 8;
                int i5 = 2;
                zzfk zzfkVar = null;
            }
        };
        final zzfq zzfqVar2 = zzfq.MESSAGE;
        final int i4 = 9;
        final String str2 = "GROUP";
        zzql = new zzfl(str2, i4, zzfqVar2, i2) { // from class: com.google.android.gms.internal.clearcut.zzfn
            {
                int i5 = 9;
                int i6 = 3;
                zzfk zzfkVar = null;
            }
        };
        final zzfq zzfqVar3 = zzfq.MESSAGE;
        final int i5 = 10;
        final String str3 = "MESSAGE";
        zzqm = new zzfl(str3, i5, zzfqVar3, i) { // from class: com.google.android.gms.internal.clearcut.zzfo
            {
                int i6 = 10;
                int i7 = 2;
                zzfk zzfkVar = null;
            }
        };
        final zzfq zzfqVar4 = zzfq.BYTE_STRING;
        final int i6 = 11;
        final String str4 = "BYTES";
        zzqn = new zzfl(str4, i6, zzfqVar4, i) { // from class: com.google.android.gms.internal.clearcut.zzfp
            {
                int i7 = 11;
                int i8 = 2;
                zzfk zzfkVar = null;
            }
        };
        zzqo = new zzfl("UINT32", 12, zzfq.INT, 0);
        zzqp = new zzfl("ENUM", 13, zzfq.ENUM, 0);
        zzqq = new zzfl("SFIXED32", 14, zzfq.INT, 5);
        zzqr = new zzfl("SFIXED64", 15, zzfq.LONG, 1);
        zzqs = new zzfl("SINT32", 16, zzfq.INT, 0);
        zzfl zzflVar = new zzfl("SINT64", 17, zzfq.LONG, 0);
        zzqt = zzflVar;
        zzqw = new zzfl[]{zzqc, zzqd, zzqe, zzqf, zzqg, zzqh, zzqi, zzqj, zzqk, zzql, zzqm, zzqn, zzqo, zzqp, zzqq, zzqr, zzqs, zzflVar};
    }

    private zzfl(String str, int i, zzfq zzfqVar, int i2) {
        this.zzqu = zzfqVar;
        this.zzqv = i2;
    }

    /* synthetic */ zzfl(String str, int i, zzfq zzfqVar, int i2, zzfk zzfkVar) {
        this(str, i, zzfqVar, i2);
    }

    public static zzfl[] values() {
        return (zzfl[]) zzqw.clone();
    }

    public final zzfq zzek() {
        return this.zzqu;
    }

    public final int zzel() {
        return this.zzqv;
    }
}
