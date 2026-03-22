package p505n;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.concurrent.CompletableFuture;
import javax.annotation.Nullable;
import org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement;
import p505n.InterfaceC4985e;

@IgnoreJRERequirement
/* renamed from: n.g */
/* loaded from: classes3.dex */
public final class C5012g extends InterfaceC4985e.a {

    /* renamed from: a */
    public static final InterfaceC4985e.a f12814a = new C5012g();

    @IgnoreJRERequirement
    /* renamed from: n.g$a */
    public static final class a<R> implements InterfaceC4985e<R, CompletableFuture<R>> {

        /* renamed from: a */
        public final Type f12815a;

        @IgnoreJRERequirement
        /* renamed from: n.g$a$a, reason: collision with other inner class name */
        public class C5140a implements InterfaceC5011f<R> {

            /* renamed from: a */
            public final CompletableFuture<R> f12816a;

            public C5140a(a aVar, CompletableFuture<R> completableFuture) {
                this.f12816a = completableFuture;
            }

            @Override // p505n.InterfaceC5011f
            /* renamed from: a */
            public void mo275a(InterfaceC4983d<R> interfaceC4983d, Throwable th) {
                this.f12816a.completeExceptionally(th);
            }

            @Override // p505n.InterfaceC5011f
            /* renamed from: b */
            public void mo276b(InterfaceC4983d<R> interfaceC4983d, C5030y<R> c5030y) {
                if (c5030y.m5685a()) {
                    this.f12816a.complete(c5030y.f12958b);
                } else {
                    this.f12816a.completeExceptionally(new C5015j(c5030y));
                }
            }
        }

        public a(Type type) {
            this.f12815a = type;
        }

        @Override // p505n.InterfaceC4985e
        /* renamed from: a */
        public Type mo277a() {
            return this.f12815a;
        }

        @Override // p505n.InterfaceC4985e
        /* renamed from: b */
        public Object mo278b(InterfaceC4983d interfaceC4983d) {
            b bVar = new b(interfaceC4983d);
            interfaceC4983d.mo5652o(new C5140a(this, bVar));
            return bVar;
        }
    }

    @IgnoreJRERequirement
    /* renamed from: n.g$b */
    public static final class b<T> extends CompletableFuture<T> {

        /* renamed from: c */
        public final InterfaceC4983d<?> f12817c;

        public b(InterfaceC4983d<?> interfaceC4983d) {
            this.f12817c = interfaceC4983d;
        }

        @Override // java.util.concurrent.CompletableFuture, java.util.concurrent.Future
        public boolean cancel(boolean z) {
            if (z) {
                this.f12817c.cancel();
            }
            return super.cancel(z);
        }
    }

    @IgnoreJRERequirement
    /* renamed from: n.g$c */
    public static final class c<R> implements InterfaceC4985e<R, CompletableFuture<C5030y<R>>> {

        /* renamed from: a */
        public final Type f12818a;

        @IgnoreJRERequirement
        /* renamed from: n.g$c$a */
        public class a implements InterfaceC5011f<R> {

            /* renamed from: a */
            public final CompletableFuture<C5030y<R>> f12819a;

            public a(c cVar, CompletableFuture<C5030y<R>> completableFuture) {
                this.f12819a = completableFuture;
            }

            @Override // p505n.InterfaceC5011f
            /* renamed from: a */
            public void mo275a(InterfaceC4983d<R> interfaceC4983d, Throwable th) {
                this.f12819a.completeExceptionally(th);
            }

            @Override // p505n.InterfaceC5011f
            /* renamed from: b */
            public void mo276b(InterfaceC4983d<R> interfaceC4983d, C5030y<R> c5030y) {
                this.f12819a.complete(c5030y);
            }
        }

        public c(Type type) {
            this.f12818a = type;
        }

        @Override // p505n.InterfaceC4985e
        /* renamed from: a */
        public Type mo277a() {
            return this.f12818a;
        }

        @Override // p505n.InterfaceC4985e
        /* renamed from: b */
        public Object mo278b(InterfaceC4983d interfaceC4983d) {
            b bVar = new b(interfaceC4983d);
            interfaceC4983d.mo5652o(new a(this, bVar));
            return bVar;
        }
    }

    @Override // p505n.InterfaceC4985e.a
    @Nullable
    /* renamed from: a */
    public InterfaceC4985e<?, ?> mo279a(Type type, Annotation[] annotationArr, C5031z c5031z) {
        if (C4984d0.m5659f(type) != CompletableFuture.class) {
            return null;
        }
        if (!(type instanceof ParameterizedType)) {
            throw new IllegalStateException("CompletableFuture return type must be parameterized as CompletableFuture<Foo> or CompletableFuture<? extends Foo>");
        }
        Type m5658e = C4984d0.m5658e(0, (ParameterizedType) type);
        if (C4984d0.m5659f(m5658e) != C5030y.class) {
            return new a(m5658e);
        }
        if (m5658e instanceof ParameterizedType) {
            return new c(C4984d0.m5658e(0, (ParameterizedType) m5658e));
        }
        throw new IllegalStateException("Response must be parameterized as Response<Foo> or Response<? extends Foo>");
    }
}
