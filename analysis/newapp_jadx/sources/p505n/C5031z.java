package p505n;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.lang.reflect.Type;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import javax.annotation.Nullable;
import kotlin.jvm.internal.Intrinsics;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p458k.C4375d0;
import p458k.C4489z;
import p458k.InterfaceC4378f;
import p505n.C4981c;
import p505n.InterfaceC4985e;
import p505n.InterfaceC5013h;

/* renamed from: n.z */
/* loaded from: classes3.dex */
public final class C5031z {

    /* renamed from: a */
    public final Map<Method, AbstractC4978a0<?>> f12959a = new ConcurrentHashMap();

    /* renamed from: b */
    public final InterfaceC4378f.a f12960b;

    /* renamed from: c */
    public final C4489z f12961c;

    /* renamed from: d */
    public final List<InterfaceC5013h.a> f12962d;

    /* renamed from: e */
    public final List<InterfaceC4985e.a> f12963e;

    /* renamed from: f */
    public final boolean f12964f;

    /* renamed from: n.z$a */
    public class a implements InvocationHandler {

        /* renamed from: c */
        public final C5027v f12965c = C5027v.f12902a;

        /* renamed from: e */
        public final Object[] f12966e = new Object[0];

        /* renamed from: f */
        public final /* synthetic */ Class f12967f;

        public a(Class cls) {
            this.f12967f = cls;
        }

        @Override // java.lang.reflect.InvocationHandler
        @Nullable
        public Object invoke(Object obj, Method method, @Nullable Object[] objArr) {
            if (method.getDeclaringClass() == Object.class) {
                return method.invoke(this, objArr);
            }
            if (objArr == null) {
                objArr = this.f12966e;
            }
            return this.f12965c.f12903b && method.isDefault() ? this.f12965c.mo5676b(method, this.f12967f, obj, objArr) : C5031z.this.m5688c(method).mo5649a(objArr);
        }
    }

    /* renamed from: n.z$b */
    public static final class b {

        /* renamed from: a */
        public final C5027v f12969a;

        /* renamed from: b */
        @Nullable
        public InterfaceC4378f.a f12970b;

        /* renamed from: c */
        @Nullable
        public C4489z f12971c;

        /* renamed from: d */
        public final List<InterfaceC5013h.a> f12972d;

        /* renamed from: e */
        public final List<InterfaceC4985e.a> f12973e;

        public b() {
            C5027v c5027v = C5027v.f12902a;
            this.f12972d = new ArrayList();
            this.f12973e = new ArrayList();
            this.f12969a = c5027v;
        }

        /* renamed from: a */
        public b m5692a(InterfaceC5013h.a aVar) {
            List<InterfaceC5013h.a> list = this.f12972d;
            Objects.requireNonNull(aVar, "factory == null");
            list.add(aVar);
            return this;
        }

        /* renamed from: b */
        public b m5693b(String toHttpUrl) {
            Objects.requireNonNull(toHttpUrl, "baseUrl == null");
            Intrinsics.checkParameterIsNotNull(toHttpUrl, "$this$toHttpUrl");
            C4489z.a aVar = new C4489z.a();
            aVar.m5302d(null, toHttpUrl);
            C4489z m5299a = aVar.m5299a();
            if ("".equals(m5299a.f12051i.get(r0.size() - 1))) {
                this.f12971c = m5299a;
                return this;
            }
            throw new IllegalArgumentException("baseUrl must end in /: " + m5299a);
        }

        /* renamed from: c */
        public C5031z m5694c() {
            if (this.f12971c == null) {
                throw new IllegalStateException("Base URL required.");
            }
            InterfaceC4378f.a aVar = this.f12970b;
            if (aVar == null) {
                aVar = new C4375d0(new C4375d0.a());
            }
            InterfaceC4378f.a aVar2 = aVar;
            Executor mo5675a = this.f12969a.mo5675a();
            ArrayList arrayList = new ArrayList(this.f12973e);
            C5027v c5027v = this.f12969a;
            C5014i c5014i = new C5014i(mo5675a);
            arrayList.addAll(c5027v.f12903b ? Arrays.asList(C5012g.f12814a, c5014i) : Collections.singletonList(c5014i));
            ArrayList arrayList2 = new ArrayList(this.f12972d.size() + 1 + (this.f12969a.f12903b ? 1 : 0));
            arrayList2.add(new C4981c());
            arrayList2.addAll(this.f12972d);
            arrayList2.addAll(this.f12969a.f12903b ? Collections.singletonList(C5023r.f12855a) : Collections.emptyList());
            return new C5031z(aVar2, this.f12971c, Collections.unmodifiableList(arrayList2), Collections.unmodifiableList(arrayList), mo5675a, false);
        }

        /* renamed from: d */
        public b m5695d(C4375d0 c4375d0) {
            Objects.requireNonNull(c4375d0, "client == null");
            this.f12970b = c4375d0;
            return this;
        }
    }

    public C5031z(InterfaceC4378f.a aVar, C4489z c4489z, List<InterfaceC5013h.a> list, List<InterfaceC4985e.a> list2, @Nullable Executor executor, boolean z) {
        this.f12960b = aVar;
        this.f12961c = c4489z;
        this.f12962d = list;
        this.f12963e = list2;
        this.f12964f = z;
    }

    /* renamed from: a */
    public InterfaceC4985e<?, ?> m5686a(Type type, Annotation[] annotationArr) {
        Objects.requireNonNull(type, "returnType == null");
        Objects.requireNonNull(annotationArr, "annotations == null");
        int indexOf = this.f12963e.indexOf(null) + 1;
        int size = this.f12963e.size();
        for (int i2 = indexOf; i2 < size; i2++) {
            InterfaceC4985e<?, ?> mo279a = this.f12963e.get(i2).mo279a(type, annotationArr, this);
            if (mo279a != null) {
                return mo279a;
            }
        }
        StringBuilder sb = new StringBuilder("Could not locate call adapter for ");
        sb.append(type);
        sb.append(".\n");
        sb.append("  Tried:");
        int size2 = this.f12963e.size();
        while (indexOf < size2) {
            sb.append("\n   * ");
            sb.append(this.f12963e.get(indexOf).getClass().getName());
            indexOf++;
        }
        throw new IllegalArgumentException(sb.toString());
    }

    /* renamed from: b */
    public <T> T m5687b(Class<T> cls) {
        if (!cls.isInterface()) {
            throw new IllegalArgumentException("API declarations must be interfaces.");
        }
        ArrayDeque arrayDeque = new ArrayDeque(1);
        arrayDeque.add(cls);
        while (!arrayDeque.isEmpty()) {
            Class<T> cls2 = (Class) arrayDeque.removeFirst();
            if (cls2.getTypeParameters().length != 0) {
                StringBuilder sb = new StringBuilder("Type parameters are unsupported on ");
                sb.append(cls2.getName());
                if (cls2 != cls) {
                    sb.append(" which is an interface of ");
                    sb.append(cls.getName());
                }
                throw new IllegalArgumentException(sb.toString());
            }
            Collections.addAll(arrayDeque, cls2.getInterfaces());
        }
        if (this.f12964f) {
            C5027v c5027v = C5027v.f12902a;
            for (Method method : cls.getDeclaredMethods()) {
                if (!(c5027v.f12903b && method.isDefault()) && !Modifier.isStatic(method.getModifiers())) {
                    m5688c(method);
                }
            }
        }
        return (T) Proxy.newProxyInstance(cls.getClassLoader(), new Class[]{cls}, new a(cls));
    }

    /* renamed from: c */
    public AbstractC4978a0<?> m5688c(Method method) {
        AbstractC4978a0<?> abstractC4978a0;
        AbstractC4978a0<?> abstractC4978a02 = this.f12959a.get(method);
        if (abstractC4978a02 != null) {
            return abstractC4978a02;
        }
        synchronized (this.f12959a) {
            abstractC4978a0 = this.f12959a.get(method);
            if (abstractC4978a0 == null) {
                abstractC4978a0 = AbstractC4978a0.m5648b(this, method);
                this.f12959a.put(method, abstractC4978a0);
            }
        }
        return abstractC4978a0;
    }

    /* renamed from: d */
    public <T> InterfaceC5013h<T, AbstractC4387j0> m5689d(Type type, Annotation[] annotationArr, Annotation[] annotationArr2) {
        Objects.requireNonNull(type, "type == null");
        Objects.requireNonNull(annotationArr, "parameterAnnotations == null");
        Objects.requireNonNull(annotationArr2, "methodAnnotations == null");
        int indexOf = this.f12962d.indexOf(null) + 1;
        int size = this.f12962d.size();
        for (int i2 = indexOf; i2 < size; i2++) {
            InterfaceC5013h<T, AbstractC4387j0> interfaceC5013h = (InterfaceC5013h<T, AbstractC4387j0>) this.f12962d.get(i2).requestBodyConverter(type, annotationArr, annotationArr2, this);
            if (interfaceC5013h != null) {
                return interfaceC5013h;
            }
        }
        StringBuilder sb = new StringBuilder("Could not locate RequestBody converter for ");
        sb.append(type);
        sb.append(".\n");
        sb.append("  Tried:");
        int size2 = this.f12962d.size();
        while (indexOf < size2) {
            sb.append("\n   * ");
            sb.append(this.f12962d.get(indexOf).getClass().getName());
            indexOf++;
        }
        throw new IllegalArgumentException(sb.toString());
    }

    /* renamed from: e */
    public <T> InterfaceC5013h<AbstractC4393m0, T> m5690e(Type type, Annotation[] annotationArr) {
        Objects.requireNonNull(type, "type == null");
        Objects.requireNonNull(annotationArr, "annotations == null");
        int indexOf = this.f12962d.indexOf(null) + 1;
        int size = this.f12962d.size();
        for (int i2 = indexOf; i2 < size; i2++) {
            InterfaceC5013h<AbstractC4393m0, T> interfaceC5013h = (InterfaceC5013h<AbstractC4393m0, T>) this.f12962d.get(i2).responseBodyConverter(type, annotationArr, this);
            if (interfaceC5013h != null) {
                return interfaceC5013h;
            }
        }
        StringBuilder sb = new StringBuilder("Could not locate ResponseBody converter for ");
        sb.append(type);
        sb.append(".\n");
        sb.append("  Tried:");
        int size2 = this.f12962d.size();
        while (indexOf < size2) {
            sb.append("\n   * ");
            sb.append(this.f12962d.get(indexOf).getClass().getName());
            indexOf++;
        }
        throw new IllegalArgumentException(sb.toString());
    }

    /* renamed from: f */
    public <T> InterfaceC5013h<T, String> m5691f(Type type, Annotation[] annotationArr) {
        Objects.requireNonNull(type, "type == null");
        Objects.requireNonNull(annotationArr, "annotations == null");
        int size = this.f12962d.size();
        for (int i2 = 0; i2 < size; i2++) {
            InterfaceC5013h<T, String> interfaceC5013h = (InterfaceC5013h<T, String>) this.f12962d.get(i2).stringConverter(type, annotationArr, this);
            if (interfaceC5013h != null) {
                return interfaceC5013h;
            }
        }
        return C4981c.d.f12803a;
    }
}
