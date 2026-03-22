package p505n;

import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.concurrent.Executor;
import javax.annotation.Nullable;
import org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement;

/* renamed from: n.v */
/* loaded from: classes3.dex */
public class C5027v {

    /* renamed from: a */
    public static final C5027v f12902a;

    /* renamed from: b */
    public final boolean f12903b;

    /* renamed from: c */
    @Nullable
    public final Constructor<MethodHandles.Lookup> f12904c;

    /* renamed from: n.v$a */
    public static final class a extends C5027v {

        /* renamed from: n.v$a$a, reason: collision with other inner class name */
        public static final class ExecutorC5141a implements Executor {

            /* renamed from: c */
            public final Handler f12905c = new Handler(Looper.getMainLooper());

            @Override // java.util.concurrent.Executor
            public void execute(Runnable runnable) {
                this.f12905c.post(runnable);
            }
        }

        public a() {
            super(Build.VERSION.SDK_INT >= 24);
        }

        @Override // p505n.C5027v
        /* renamed from: a */
        public Executor mo5675a() {
            return new ExecutorC5141a();
        }

        @Override // p505n.C5027v
        @Nullable
        /* renamed from: b */
        public Object mo5676b(Method method, Class<?> cls, Object obj, Object... objArr) {
            if (Build.VERSION.SDK_INT >= 26) {
                return super.mo5676b(method, cls, obj, objArr);
            }
            throw new UnsupportedOperationException("Calling default methods on API 24 and 25 is not supported");
        }
    }

    static {
        f12902a = "Dalvik".equals(System.getProperty("java.vm.name")) ? new a() : new C5027v(true);
    }

    public C5027v(boolean z) {
        this.f12903b = z;
        Constructor<MethodHandles.Lookup> constructor = null;
        if (z) {
            try {
                constructor = MethodHandles.Lookup.class.getDeclaredConstructor(Class.class, Integer.TYPE);
                constructor.setAccessible(true);
            } catch (NoClassDefFoundError | NoSuchMethodException unused) {
            }
        }
        this.f12904c = constructor;
    }

    @Nullable
    /* renamed from: a */
    public Executor mo5675a() {
        return null;
    }

    @Nullable
    @IgnoreJRERequirement
    /* renamed from: b */
    public Object mo5676b(Method method, Class<?> cls, Object obj, Object... objArr) {
        Constructor<MethodHandles.Lookup> constructor = this.f12904c;
        return (constructor != null ? constructor.newInstance(cls, -1) : MethodHandles.lookup()).unreflectSpecial(method, cls).bindTo(obj).invokeWithArguments(objArr);
    }
}
