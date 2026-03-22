package p505n;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import javax.annotation.Nullable;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;

/* renamed from: n.h */
/* loaded from: classes3.dex */
public interface InterfaceC5013h<F, T> {

    /* renamed from: n.h$a */
    public static abstract class a {
        public static Type getParameterUpperBound(int i2, ParameterizedType parameterizedType) {
            return C4984d0.m5658e(i2, parameterizedType);
        }

        public static Class<?> getRawType(Type type) {
            return C4984d0.m5659f(type);
        }

        @Nullable
        public InterfaceC5013h<?, AbstractC4387j0> requestBodyConverter(Type type, Annotation[] annotationArr, Annotation[] annotationArr2, C5031z c5031z) {
            return null;
        }

        @Nullable
        public InterfaceC5013h<AbstractC4393m0, ?> responseBodyConverter(Type type, Annotation[] annotationArr, C5031z c5031z) {
            return null;
        }

        @Nullable
        public InterfaceC5013h<?, String> stringConverter(Type type, Annotation[] annotationArr, C5031z c5031z) {
            return null;
        }
    }

    @Nullable
    T convert(F f2);
}
