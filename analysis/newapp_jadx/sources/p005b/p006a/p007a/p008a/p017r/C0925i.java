package p005b.p006a.p007a.p008a.p017r;

import android.content.SharedPreferences;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

/* renamed from: b.a.a.a.r.i */
/* loaded from: classes2.dex */
public final class C0925i {

    /* renamed from: b */
    @NotNull
    public static String f438b = "";

    /* renamed from: a */
    @NotNull
    public static final C0925i f437a = new C0925i();

    /* renamed from: c */
    @NotNull
    public static final ArrayList<C0924h> f439c = CollectionsKt__CollectionsKt.arrayListOf(new C0924h("", "http://api-douman.sljghdlqpa.com/mhapi/", true), new C0924h("", "http://api-douman.kicfoakjvf.com/mhapi/", true), new C0924h("", "http://api-douman.ku0g6y1ag9.com/mhapi/", true), new C0924h("", "http://api-douman.uxavma85y8.com/mhapi/", true), new C0924h("", "http://api.235094fc787c80ad.com/mhapi/", false), new C0924h("", "http://api.4dd726dc92e61823.com/mhapi/", false), new C0924h("", "http://api.8c477ebb2e20bf42.com/mhapi/", false), new C0924h("", "http://api.c984d578410e1474.com/mhapi/", false));

    /* renamed from: d */
    @NotNull
    public static final ArrayList<C0924h> f440d = CollectionsKt__CollectionsKt.arrayListOf(new C0924h("hw1", "http://api.4gipgttt.com/mhapi/", false), new C0924h("hw2", "http://api.24oamdol.com/mhapi/", false), new C0924h("hw3", "http://api.s5u0ze3y.com/mhapi/", false), new C0924h("ch1", "http://api.3xfp3x4p.com/mhapi/", false), new C0924h("ch2", "http://api.9wwwiiol.com/mhapi/", false), new C0924h("ch3", "http://api.bmyr45l1.com/mhapi/", false));

    @NotNull
    /* renamed from: a */
    public final String m269a() {
        ArrayList<C0924h> arrayList = f439c;
        return C2354n.m2414N0(arrayList) ? ((C0924h) CollectionsKt___CollectionsKt.first((List) arrayList)).f435b : "";
    }

    @NotNull
    /* renamed from: b */
    public final String m270b() {
        if (TextUtils.isEmpty(f438b)) {
            String m269a = m269a();
            Intrinsics.checkNotNullParameter("SP_BASE_URL", "key");
            Intrinsics.checkNotNullParameter(m269a, "default");
            ApplicationC2828a applicationC2828a = C2827a.f7670a;
            if (applicationC2828a == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
            Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
            String string = sharedPreferences.getString("SP_BASE_URL", m269a);
            Intrinsics.checkNotNull(string);
            if (TextUtils.isEmpty(string)) {
                string = "http://api.jopejrlsto.com/mhapi/";
            }
            f438b = string;
        }
        return f438b;
    }
}
