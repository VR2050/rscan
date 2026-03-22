package p379c.p380a.p381a;

import java.util.Iterator;
import java.util.List;
import kotlin.jvm.JvmField;
import kotlin.sequences.SequencesKt__SequencesKt;
import kotlin.sequences.SequencesKt___SequencesKt;
import kotlinx.coroutines.internal.MainDispatcherFactory;
import org.jetbrains.annotations.NotNull;
import p000.C0000a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3077l1;

/* renamed from: c.a.a.m */
/* loaded from: classes2.dex */
public final class C2964m {

    /* renamed from: a */
    public static final boolean f8126a;

    /* renamed from: b */
    @JvmField
    @NotNull
    public static final AbstractC3077l1 f8127b;

    static {
        C2964m c2964m = new C2964m();
        String m2421P1 = C2354n.m2421P1("kotlinx.coroutines.fast.service.loader");
        f8126a = m2421P1 != null ? Boolean.parseBoolean(m2421P1) : true;
        f8127b = c2964m.m3443a();
    }

    /* renamed from: a */
    public final AbstractC3077l1 m3443a() {
        Object obj;
        List<? extends MainDispatcherFactory> list = SequencesKt___SequencesKt.toList(SequencesKt__SequencesKt.asSequence(C0000a.m0a()));
        Iterator it = list.iterator();
        if (it.hasNext()) {
            Object next = it.next();
            if (it.hasNext()) {
                int loadPriority = ((MainDispatcherFactory) next).getLoadPriority();
                do {
                    Object next2 = it.next();
                    int loadPriority2 = ((MainDispatcherFactory) next2).getLoadPriority();
                    if (loadPriority < loadPriority2) {
                        next = next2;
                        loadPriority = loadPriority2;
                    }
                } while (it.hasNext());
            }
            obj = next;
        } else {
            obj = null;
        }
        MainDispatcherFactory mainDispatcherFactory = (MainDispatcherFactory) obj;
        if (mainDispatcherFactory != null) {
            try {
                AbstractC3077l1 createDispatcher = mainDispatcherFactory.createDispatcher(list);
                if (createDispatcher != null) {
                    return createDispatcher;
                }
            } catch (Throwable th) {
                mainDispatcherFactory.hintOnError();
                throw th;
            }
        }
        throw new IllegalStateException("Module with the Main dispatcher is missing. Add dependency providing the Main dispatcher, e.g. 'kotlinx-coroutines-android' and ensure it has the same version as 'kotlinx-coroutines-core'");
    }
}
