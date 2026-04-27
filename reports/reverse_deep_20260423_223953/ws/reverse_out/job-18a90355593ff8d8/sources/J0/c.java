package J0;

import P0.d;
import com.facebook.imagepipeline.producers.d0;
import com.facebook.imagepipeline.producers.l0;
import h0.InterfaceC0547c;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c extends J0.a {

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public static final a f1454j = new a(null);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final InterfaceC0547c a(d0 d0Var, l0 l0Var, d dVar) {
            j.f(d0Var, "producer");
            j.f(l0Var, "settableProducerContext");
            j.f(dVar, "listener");
            return new c(d0Var, l0Var, dVar, null);
        }

        private a() {
        }
    }

    public /* synthetic */ c(d0 d0Var, l0 l0Var, d dVar, DefaultConstructorMarker defaultConstructorMarker) {
        this(d0Var, l0Var, dVar);
    }

    private c(d0 d0Var, l0 l0Var, d dVar) {
        super(d0Var, l0Var, dVar);
    }
}
