package p005b.p310s.p311a;

import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p199l.p266d.EnumC2497a;

/* renamed from: b.s.a.j */
/* loaded from: classes2.dex */
public final class C2740j {

    /* renamed from: a */
    public static final Set<EnumC2497a> f7485a;

    /* renamed from: b */
    public static final Set<EnumC2497a> f7486b;

    /* renamed from: c */
    public static final Set<EnumC2497a> f7487c;

    /* renamed from: d */
    public static final Set<EnumC2497a> f7488d;

    /* renamed from: e */
    public static final Set<EnumC2497a> f7489e;

    /* renamed from: f */
    public static final Set<EnumC2497a> f7490f;

    /* renamed from: g */
    public static final Set<EnumC2497a> f7491g;

    /* renamed from: h */
    public static final Map<String, Set<EnumC2497a>> f7492h;

    static {
        Pattern.compile(ChineseToPinyinResource.Field.COMMA);
        EnumSet of = EnumSet.of(EnumC2497a.QR_CODE);
        f7488d = of;
        EnumSet of2 = EnumSet.of(EnumC2497a.DATA_MATRIX);
        f7489e = of2;
        EnumSet of3 = EnumSet.of(EnumC2497a.AZTEC);
        f7490f = of3;
        EnumSet of4 = EnumSet.of(EnumC2497a.PDF_417);
        f7491g = of4;
        EnumSet of5 = EnumSet.of(EnumC2497a.UPC_A, EnumC2497a.UPC_E, EnumC2497a.EAN_13, EnumC2497a.EAN_8, EnumC2497a.RSS_14, EnumC2497a.RSS_EXPANDED);
        f7485a = of5;
        EnumSet of6 = EnumSet.of(EnumC2497a.CODE_39, EnumC2497a.CODE_93, EnumC2497a.CODE_128, EnumC2497a.ITF, EnumC2497a.CODABAR);
        f7486b = of6;
        EnumSet copyOf = EnumSet.copyOf((Collection) of5);
        f7487c = copyOf;
        copyOf.addAll(of6);
        HashMap hashMap = new HashMap();
        f7492h = hashMap;
        hashMap.put("ONE_D_MODE", copyOf);
        hashMap.put("PRODUCT_MODE", of5);
        hashMap.put("QR_CODE_MODE", of);
        hashMap.put("DATA_MATRIX_MODE", of2);
        hashMap.put("AZTEC_MODE", of3);
        hashMap.put("PDF417_MODE", of4);
    }
}
