package D1;

import com.facebook.react.bridge.ReadableMap;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class b extends T0.b {

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    public static final a f599D = new a(null);

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final ReadableMap f600B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private final D1.a f601C;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ b c(a aVar, T0.c cVar, ReadableMap readableMap, D1.a aVar2, int i3, Object obj) {
            if ((i3 & 4) != 0) {
                aVar2 = D1.a.f593b;
            }
            return aVar.b(cVar, readableMap, aVar2);
        }

        public final b a(T0.c cVar, ReadableMap readableMap) {
            j.f(cVar, "builder");
            return c(this, cVar, readableMap, null, 4, null);
        }

        public final b b(T0.c cVar, ReadableMap readableMap, D1.a aVar) {
            j.f(cVar, "builder");
            j.f(aVar, "cacheControl");
            return new b(cVar, readableMap, aVar, null);
        }

        private a() {
        }
    }

    public /* synthetic */ b(T0.c cVar, ReadableMap readableMap, D1.a aVar, DefaultConstructorMarker defaultConstructorMarker) {
        this(cVar, readableMap, aVar);
    }

    public static final b A(T0.c cVar, ReadableMap readableMap) {
        return f599D.a(cVar, readableMap);
    }

    public final D1.a B() {
        return this.f601C;
    }

    public final ReadableMap C() {
        return this.f600B;
    }

    private b(T0.c cVar, ReadableMap readableMap, D1.a aVar) {
        super(cVar);
        this.f600B = readableMap;
        this.f601C = aVar;
    }
}
