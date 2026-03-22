package p005b.p190k.p191a.p192a;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
/* renamed from: b.k.a.a.b */
/* loaded from: classes.dex */
public @interface InterfaceC1881b {

    /* renamed from: b.k.a.a.b$a */
    public enum a {
        LEFT(1),
        RIGHT(2),
        TOP(4),
        BOTTOM(8);


        /* renamed from: i */
        public final int f2903i;

        a(int i2) {
            this.f2903i = i2;
        }
    }

    /* renamed from: b.k.a.a.b$b */
    public enum b {
        FULLSCREEN(0),
        EDGE(1);


        /* renamed from: g */
        public final int f2907g;

        b(int i2) {
            this.f2907g = i2;
        }
    }

    /* renamed from: b.k.a.a.b$c */
    public enum c {
        PARALLAX(1),
        COVER(0),
        SLIDE(2);


        /* renamed from: h */
        public final int f2912h;

        c(int i2) {
            this.f2912h = i2;
        }
    }

    a edge() default a.LEFT;

    b edgeMode() default b.EDGE;

    c layout() default c.PARALLAX;
}
