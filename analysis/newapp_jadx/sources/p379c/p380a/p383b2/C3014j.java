package p379c.p380a.p383b2;

import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* JADX INFO: Add missing generic type declarations: [T] */
/* renamed from: c.a.b2.j */
/* loaded from: classes2.dex */
public final class C3014j<T> implements InterfaceC3006b<T> {

    /* renamed from: a */
    public final /* synthetic */ InterfaceC3006b f8261a;

    /* renamed from: c.a.b2.j$a */
    public static final class a implements InterfaceC3007c<InterfaceC3006b<? extends T>> {

        /* renamed from: c */
        public final /* synthetic */ InterfaceC3007c f8262c;

        public a(InterfaceC3007c interfaceC3007c) {
            this.f8262c = interfaceC3007c;
        }

        @Override // p379c.p380a.p383b2.InterfaceC3007c
        @Nullable
        public Object emit(Object obj, @NotNull Continuation continuation) {
            Object mo289a = ((InterfaceC3006b) obj).mo289a(this.f8262c, continuation);
            return mo289a == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo289a : Unit.INSTANCE;
        }
    }

    public C3014j(InterfaceC3006b interfaceC3006b) {
        this.f8261a = interfaceC3006b;
    }

    @Override // p379c.p380a.p383b2.InterfaceC3006b
    @Nullable
    /* renamed from: a */
    public Object mo289a(@NotNull InterfaceC3007c interfaceC3007c, @NotNull Continuation continuation) {
        Object mo289a = this.f8261a.mo289a(new a(interfaceC3007c), continuation);
        return mo289a == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo289a : Unit.INSTANCE;
    }
}
