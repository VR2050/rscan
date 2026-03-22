package p005b.p199l.p258c.p259b0;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD, ElementType.METHOD})
@Documented
@Retention(RetentionPolicy.RUNTIME)
/* renamed from: b.l.c.b0.b */
/* loaded from: classes2.dex */
public @interface InterfaceC2418b {
    String[] alternate() default {};

    String value();
}
