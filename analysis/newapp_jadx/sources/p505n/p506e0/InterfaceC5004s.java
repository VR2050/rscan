package p505n.p506e0;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.PARAMETER})
@Documented
@Retention(RetentionPolicy.RUNTIME)
/* renamed from: n.e0.s */
/* loaded from: classes3.dex */
public @interface InterfaceC5004s {
    boolean encoded() default false;

    String value();
}
