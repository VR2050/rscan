package p005b.p006a.p007a.p008a.p009a;

import com.jbzd.media.movecartoons.bean.response.UploadBean;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.a.a.a.a.l0 */
/* loaded from: classes2.dex */
public final class C0857l0 {

    /* renamed from: a */
    @NotNull
    public static final C0857l0 f275a = null;

    /* renamed from: b */
    @NotNull
    public static final C0857l0 f276b;

    /* renamed from: c */
    @NotNull
    public final Lazy f277c = LazyKt__LazyJVMKt.lazy(c.f283c);

    /* renamed from: d */
    @NotNull
    public final Lazy f278d = LazyKt__LazyJVMKt.lazy(b.f282c);

    /* renamed from: e */
    @NotNull
    public final Lazy f279e = LazyKt__LazyJVMKt.lazy(d.f284c);

    /* renamed from: b.a.a.a.a.l0$a */
    public static final class a {

        /* renamed from: a */
        @NotNull
        public static final a f280a = null;

        /* renamed from: b */
        @NotNull
        public static final C0857l0 f281b = new C0857l0();
    }

    /* renamed from: b.a.a.a.a.l0$b */
    public static final class b extends Lambda implements Function0<HashMap<String, RunnableC0849h0>> {

        /* renamed from: c */
        public static final b f282c = new b();

        public b() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public HashMap<String, RunnableC0849h0> invoke() {
            return new HashMap<>();
        }
    }

    /* renamed from: b.a.a.a.a.l0$c */
    public static final class c extends Lambda implements Function0<ExecutorService> {

        /* renamed from: c */
        public static final c f283c = new c();

        public c() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public ExecutorService invoke() {
            return Executors.newCachedThreadPool();
        }
    }

    /* renamed from: b.a.a.a.a.l0$d */
    public static final class d extends Lambda implements Function0<LinkedBlockingQueue<UploadBean>> {

        /* renamed from: c */
        public static final d f284c = new d();

        public d() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public LinkedBlockingQueue<UploadBean> invoke() {
            return new LinkedBlockingQueue<>();
        }
    }

    static {
        a aVar = a.f280a;
        f276b = a.f281b;
    }
}
