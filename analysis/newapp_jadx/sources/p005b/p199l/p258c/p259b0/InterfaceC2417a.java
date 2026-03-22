package p005b.p199l.p258c.p259b0;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.TYPE, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
/* renamed from: b.l.c.b0.a */
/* loaded from: classes2.dex */
public @interface InterfaceC2417a {
    boolean nullSafe() default true;

    Class<?> value();
}
