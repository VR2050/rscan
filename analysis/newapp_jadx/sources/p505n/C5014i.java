package p505n;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.concurrent.Executor;
import javax.annotation.Nullable;
import p458k.C4381g0;
import p505n.C5014i;
import p505n.InterfaceC4985e;

/* renamed from: n.i */
/* loaded from: classes3.dex */
public final class C5014i extends InterfaceC4985e.a {

    /* renamed from: a */
    @Nullable
    public final Executor f12820a;

    /* renamed from: n.i$a */
    public class a implements InterfaceC4985e<Object, InterfaceC4983d<?>> {

        /* renamed from: a */
        public final /* synthetic */ Type f12821a;

        /* renamed from: b */
        public final /* synthetic */ Executor f12822b;

        public a(C5014i c5014i, Type type, Executor executor) {
            this.f12821a = type;
            this.f12822b = executor;
        }

        @Override // p505n.InterfaceC4985e
        /* renamed from: a */
        public Type mo277a() {
            return this.f12821a;
        }

        @Override // p505n.InterfaceC4985e
        /* renamed from: b */
        public InterfaceC4983d<?> mo278b(InterfaceC4983d<Object> interfaceC4983d) {
            Executor executor = this.f12822b;
            return executor == null ? interfaceC4983d : new b(executor, interfaceC4983d);
        }
    }

    /* renamed from: n.i$b */
    public static final class b<T> implements InterfaceC4983d<T> {

        /* renamed from: c */
        public final Executor f12823c;

        /* renamed from: e */
        public final InterfaceC4983d<T> f12824e;

        /* renamed from: n.i$b$a */
        public class a implements InterfaceC5011f<T> {

            /* renamed from: a */
            public final /* synthetic */ InterfaceC5011f f12825a;

            public a(InterfaceC5011f interfaceC5011f) {
                this.f12825a = interfaceC5011f;
            }

            @Override // p505n.InterfaceC5011f
            /* renamed from: a */
            public void mo275a(InterfaceC4983d<T> interfaceC4983d, final Throwable th) {
                Executor executor = b.this.f12823c;
                final InterfaceC5011f interfaceC5011f = this.f12825a;
                executor.execute(new Runnable() { // from class: n.a
                    @Override // java.lang.Runnable
                    public final void run() {
                        C5014i.b.a aVar = C5014i.b.a.this;
                        interfaceC5011f.mo275a(C5014i.b.this, th);
                    }
                });
            }

            @Override // p505n.InterfaceC5011f
            /* renamed from: b */
            public void mo276b(InterfaceC4983d<T> interfaceC4983d, final C5030y<T> c5030y) {
                Executor executor = b.this.f12823c;
                final InterfaceC5011f interfaceC5011f = this.f12825a;
                executor.execute(new Runnable() { // from class: n.b
                    @Override // java.lang.Runnable
                    public final void run() {
                        C5014i.b.a aVar = C5014i.b.a.this;
                        InterfaceC5011f interfaceC5011f2 = interfaceC5011f;
                        C5030y c5030y2 = c5030y;
                        if (C5014i.b.this.f12824e.mo5650b()) {
                            interfaceC5011f2.mo275a(C5014i.b.this, new IOException("Canceled"));
                        } else {
                            interfaceC5011f2.mo276b(C5014i.b.this, c5030y2);
                        }
                    }
                });
            }
        }

        public b(Executor executor, InterfaceC4983d<T> interfaceC4983d) {
            this.f12823c = executor;
            this.f12824e = interfaceC4983d;
        }

        @Override // p505n.InterfaceC4983d
        /* renamed from: b */
        public boolean mo5650b() {
            return this.f12824e.mo5650b();
        }

        @Override // p505n.InterfaceC4983d
        public void cancel() {
            this.f12824e.cancel();
        }

        public Object clone() {
            return new b(this.f12823c, this.f12824e.mo5653q());
        }

        @Override // p505n.InterfaceC4983d
        /* renamed from: e */
        public C4381g0 mo5651e() {
            return this.f12824e.mo5651e();
        }

        @Override // p505n.InterfaceC4983d
        /* renamed from: o */
        public void mo5652o(InterfaceC5011f<T> interfaceC5011f) {
            this.f12824e.mo5652o(new a(interfaceC5011f));
        }

        @Override // p505n.InterfaceC4983d
        /* renamed from: q */
        public InterfaceC4983d<T> mo5653q() {
            return new b(this.f12823c, this.f12824e.mo5653q());
        }
    }

    public C5014i(@Nullable Executor executor) {
        this.f12820a = executor;
    }

    @Override // p505n.InterfaceC4985e.a
    @Nullable
    /* renamed from: a */
    public InterfaceC4985e<?, ?> mo279a(Type type, Annotation[] annotationArr, C5031z c5031z) {
        if (C4984d0.m5659f(type) != InterfaceC4983d.class) {
            return null;
        }
        if (type instanceof ParameterizedType) {
            return new a(this, C4984d0.m5658e(0, (ParameterizedType) type), C4984d0.m5662i(annotationArr, InterfaceC4980b0.class) ? null : this.f12820a);
        }
        throw new IllegalArgumentException("Call return type must be parameterized as Call<Foo> or Call<? extends Foo>");
    }
}
