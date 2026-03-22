package p005b.p006a.p007a.p008a.p009a;

import android.content.res.Resources;
import com.jbzd.media.movecartoons.MyApp;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.a.a.a.a.c0 */
/* loaded from: classes2.dex */
public final class C0839c0 {

    /* renamed from: a */
    @NotNull
    public static final C0839c0 f232a = null;

    /* renamed from: b */
    @NotNull
    public static final Lazy f233b = LazyKt__LazyJVMKt.lazy(a.f234c);

    /* renamed from: b.a.a.a.a.c0$a */
    public static final class a extends Lambda implements Function0<Resources> {

        /* renamed from: c */
        public static final a f234c = new a();

        public a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public Resources invoke() {
            MyApp myApp = MyApp.f9891f;
            return MyApp.m4183d().getResources();
        }
    }
}
