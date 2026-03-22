package p505n;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Optional;
import javax.annotation.Nullable;
import org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement;
import p458k.AbstractC4393m0;
import p505n.InterfaceC5013h;

@IgnoreJRERequirement
/* renamed from: n.r */
/* loaded from: classes3.dex */
public final class C5023r extends InterfaceC5013h.a {

    /* renamed from: a */
    public static final InterfaceC5013h.a f12855a = new C5023r();

    @IgnoreJRERequirement
    /* renamed from: n.r$a */
    public static final class a<T> implements InterfaceC5013h<AbstractC4393m0, Optional<T>> {

        /* renamed from: a */
        public final InterfaceC5013h<AbstractC4393m0, T> f12856a;

        public a(InterfaceC5013h<AbstractC4393m0, T> interfaceC5013h) {
            this.f12856a = interfaceC5013h;
        }

        @Override // p505n.InterfaceC5013h
        public Object convert(AbstractC4393m0 abstractC4393m0) {
            return Optional.ofNullable(this.f12856a.convert(abstractC4393m0));
        }
    }

    @Override // p505n.InterfaceC5013h.a
    @Nullable
    public InterfaceC5013h<AbstractC4393m0, ?> responseBodyConverter(Type type, Annotation[] annotationArr, C5031z c5031z) {
        if (InterfaceC5013h.a.getRawType(type) != Optional.class) {
            return null;
        }
        return new a(c5031z.m5690e(InterfaceC5013h.a.getParameterUpperBound(0, (ParameterizedType) type), annotationArr));
    }
}
