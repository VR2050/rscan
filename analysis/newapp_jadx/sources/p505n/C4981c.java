package p505n;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import javax.annotation.Nullable;
import kotlin.Unit;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p505n.InterfaceC5013h;
import p505n.p506e0.InterfaceC5008w;

/* renamed from: n.c */
/* loaded from: classes3.dex */
public final class C4981c extends InterfaceC5013h.a {

    /* renamed from: a */
    public boolean f12799a = true;

    /* renamed from: n.c$a */
    public static final class a implements InterfaceC5013h<AbstractC4393m0, AbstractC4393m0> {

        /* renamed from: a */
        public static final a f12800a = new a();

        @Override // p505n.InterfaceC5013h
        public AbstractC4393m0 convert(AbstractC4393m0 abstractC4393m0) {
            AbstractC4393m0 abstractC4393m02 = abstractC4393m0;
            try {
                return C4984d0.m5654a(abstractC4393m02);
            } finally {
                abstractC4393m02.close();
            }
        }
    }

    /* renamed from: n.c$b */
    public static final class b implements InterfaceC5013h<AbstractC4387j0, AbstractC4387j0> {

        /* renamed from: a */
        public static final b f12801a = new b();

        @Override // p505n.InterfaceC5013h
        public AbstractC4387j0 convert(AbstractC4387j0 abstractC4387j0) {
            return abstractC4387j0;
        }
    }

    /* renamed from: n.c$c */
    public static final class c implements InterfaceC5013h<AbstractC4393m0, AbstractC4393m0> {

        /* renamed from: a */
        public static final c f12802a = new c();

        @Override // p505n.InterfaceC5013h
        public AbstractC4393m0 convert(AbstractC4393m0 abstractC4393m0) {
            return abstractC4393m0;
        }
    }

    /* renamed from: n.c$d */
    public static final class d implements InterfaceC5013h<Object, String> {

        /* renamed from: a */
        public static final d f12803a = new d();

        @Override // p505n.InterfaceC5013h
        public String convert(Object obj) {
            return obj.toString();
        }
    }

    /* renamed from: n.c$e */
    public static final class e implements InterfaceC5013h<AbstractC4393m0, Unit> {

        /* renamed from: a */
        public static final e f12804a = new e();

        @Override // p505n.InterfaceC5013h
        public Unit convert(AbstractC4393m0 abstractC4393m0) {
            abstractC4393m0.close();
            return Unit.INSTANCE;
        }
    }

    /* renamed from: n.c$f */
    public static final class f implements InterfaceC5013h<AbstractC4393m0, Void> {

        /* renamed from: a */
        public static final f f12805a = new f();

        @Override // p505n.InterfaceC5013h
        public Void convert(AbstractC4393m0 abstractC4393m0) {
            abstractC4393m0.close();
            return null;
        }
    }

    @Override // p505n.InterfaceC5013h.a
    @Nullable
    public InterfaceC5013h<?, AbstractC4387j0> requestBodyConverter(Type type, Annotation[] annotationArr, Annotation[] annotationArr2, C5031z c5031z) {
        if (AbstractC4387j0.class.isAssignableFrom(C4984d0.m5659f(type))) {
            return b.f12801a;
        }
        return null;
    }

    @Override // p505n.InterfaceC5013h.a
    @Nullable
    public InterfaceC5013h<AbstractC4393m0, ?> responseBodyConverter(Type type, Annotation[] annotationArr, C5031z c5031z) {
        if (type == AbstractC4393m0.class) {
            return C4984d0.m5662i(annotationArr, InterfaceC5008w.class) ? c.f12802a : a.f12800a;
        }
        if (type == Void.class) {
            return f.f12805a;
        }
        if (!this.f12799a || type != Unit.class) {
            return null;
        }
        try {
            return e.f12804a;
        } catch (NoClassDefFoundError unused) {
            this.f12799a = false;
            return null;
        }
    }
}
