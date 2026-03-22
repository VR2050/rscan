package p005b.p199l.p258c.p260c0;

import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import p005b.p131d.p132a.p133a.C1499a;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: b.l.c.c0.f */
/* loaded from: classes2.dex */
public class C2448f<T> implements InterfaceC2462t<T> {

    /* renamed from: a */
    public final AbstractC2468z f6587a;

    /* renamed from: b */
    public final /* synthetic */ Class f6588b;

    /* renamed from: c */
    public final /* synthetic */ Type f6589c;

    public C2448f(C2449g c2449g, Class cls, Type type) {
        AbstractC2468z c2467y;
        this.f6588b = cls;
        this.f6589c = type;
        try {
            Class<?> cls2 = Class.forName("sun.misc.Unsafe");
            Field declaredField = cls2.getDeclaredField("theUnsafe");
            declaredField.setAccessible(true);
            c2467y = new C2464v(cls2.getMethod("allocateInstance", Class.class), declaredField.get(null));
        } catch (Exception unused) {
            try {
                try {
                    Method declaredMethod = ObjectStreamClass.class.getDeclaredMethod("getConstructorId", Class.class);
                    declaredMethod.setAccessible(true);
                    int intValue = ((Integer) declaredMethod.invoke(null, Object.class)).intValue();
                    Method declaredMethod2 = ObjectStreamClass.class.getDeclaredMethod("newInstance", Class.class, Integer.TYPE);
                    declaredMethod2.setAccessible(true);
                    c2467y = new C2465w(declaredMethod2, intValue);
                } catch (Exception unused2) {
                    Method declaredMethod3 = ObjectInputStream.class.getDeclaredMethod("newInstance", Class.class, Class.class);
                    declaredMethod3.setAccessible(true);
                    c2467y = new C2466x(declaredMethod3);
                }
            } catch (Exception unused3) {
                c2467y = new C2467y();
            }
        }
        this.f6587a = c2467y;
    }

    @Override // p005b.p199l.p258c.p260c0.InterfaceC2462t
    /* renamed from: a */
    public T mo2810a() {
        try {
            return (T) this.f6587a.mo2824b(this.f6588b);
        } catch (Exception e2) {
            StringBuilder m586H = C1499a.m586H("Unable to invoke no-args constructor for ");
            m586H.append(this.f6589c);
            m586H.append(". Registering an InstanceCreator with Gson for this type may fix this problem.");
            throw new RuntimeException(m586H.toString(), e2);
        }
    }
}
