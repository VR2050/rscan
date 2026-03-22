package p005b.p006a.p007a.p008a.p009a;

import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.BloggerOrderBean;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.a.a.a.a.a */
/* loaded from: classes2.dex */
public final class C0834a {

    /* renamed from: a */
    @NotNull
    public static final C0834a f214a = null;

    /* renamed from: b */
    @NotNull
    public static final Lazy f215b = LazyKt__LazyJVMKt.lazy(b.f221c);

    /* renamed from: c */
    @NotNull
    public static final Lazy f216c = LazyKt__LazyJVMKt.lazy(a.f219e);

    /* renamed from: d */
    @NotNull
    public static final Lazy f217d = LazyKt__LazyJVMKt.lazy(a.f218c);

    /* renamed from: b.a.a.a.a.a$a */
    /* loaded from: classes.dex */
    public static final class a extends Lambda implements Function0<ArrayList<String>> {

        /* renamed from: c */
        public static final a f218c = new a(0);

        /* renamed from: e */
        public static final a f219e = new a(1);

        /* renamed from: f */
        public final /* synthetic */ int f220f;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(int i2) {
            super(0);
            this.f220f = i2;
        }

        @Override // kotlin.jvm.functions.Function0
        public final ArrayList<String> invoke() {
            int i2 = this.f220f;
            if (i2 == 0) {
                MyApp myApp = MyApp.f9891f;
                String string = MyApp.m4184e().getString(R.string.canvas_long_video);
                Intrinsics.checkNotNullExpressionValue(string, "MyApp.resourses.getString(R.string.canvas_long_video)");
                String string2 = MyApp.m4184e().getString(R.string.canvas_short_video);
                Intrinsics.checkNotNullExpressionValue(string2, "MyApp.resourses.getString(R.string.canvas_short_video)");
                return CollectionsKt__CollectionsKt.arrayListOf(string, string2);
            }
            if (i2 != 1) {
                throw null;
            }
            MyApp myApp2 = MyApp.f9891f;
            String string3 = MyApp.m4184e().getString(R.string.order_by_composite);
            Intrinsics.checkNotNullExpressionValue(string3, "MyApp.resourses.getString(R.string.order_by_composite)");
            String string4 = MyApp.m4184e().getString(R.string.order_by_new);
            Intrinsics.checkNotNullExpressionValue(string4, "MyApp.resourses.getString(R.string.order_by_new)");
            String string5 = MyApp.m4184e().getString(R.string.order_by_play_num);
            Intrinsics.checkNotNullExpressionValue(string5, "MyApp.resourses.getString(R.string.order_by_play_num)");
            String string6 = MyApp.m4184e().getString(R.string.order_by_favorite);
            Intrinsics.checkNotNullExpressionValue(string6, "MyApp.resourses.getString(R.string.order_by_favorite)");
            return CollectionsKt__CollectionsKt.arrayListOf(string3, string4, string5, string6);
        }
    }

    /* renamed from: b.a.a.a.a.a$b */
    public static final class b extends Lambda implements Function0<ArrayList<C0835a0>> {

        /* renamed from: c */
        public static final b f221c = new b();

        public b() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public ArrayList<C0835a0> invoke() {
            MyApp myApp = MyApp.f9891f;
            String string = MyApp.m4184e().getString(R.string.order_by_composite);
            Intrinsics.checkNotNullExpressionValue(string, "MyApp.resourses.getString(R.string.order_by_composite)");
            String string2 = MyApp.m4184e().getString(R.string.order_by_new);
            Intrinsics.checkNotNullExpressionValue(string2, "MyApp.resourses.getString(R.string.order_by_new)");
            String string3 = MyApp.m4184e().getString(R.string.order_by_play_num);
            Intrinsics.checkNotNullExpressionValue(string3, "MyApp.resourses.getString(R.string.order_by_play_num)");
            String string4 = MyApp.m4184e().getString(R.string.order_by_favorite);
            Intrinsics.checkNotNullExpressionValue(string4, "MyApp.resourses.getString(R.string.order_by_favorite)");
            return CollectionsKt__CollectionsKt.arrayListOf(new C0835a0("composite_sort", string), new C0835a0(BloggerOrderBean.order_new, string2), new C0835a0("play_num", string3), new C0835a0("love", string4));
        }
    }

    @NotNull
    /* renamed from: a */
    public static final ArrayList<C0835a0> m173a() {
        return (ArrayList) f215b.getValue();
    }
}
