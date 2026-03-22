package p005b.p143g.p144a.p147m.p154u;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;

/* renamed from: b.g.a.m.u.n */
/* loaded from: classes.dex */
public interface InterfaceC1672n<Model, Data> {

    /* renamed from: b.g.a.m.u.n$a */
    public static class a<Data> {

        /* renamed from: a */
        public final InterfaceC1579k f2381a;

        /* renamed from: b */
        public final List<InterfaceC1579k> f2382b;

        /* renamed from: c */
        public final InterfaceC1590d<Data> f2383c;

        public a(@NonNull InterfaceC1579k interfaceC1579k, @NonNull InterfaceC1590d<Data> interfaceC1590d) {
            List<InterfaceC1579k> emptyList = Collections.emptyList();
            Objects.requireNonNull(interfaceC1579k, "Argument must not be null");
            this.f2381a = interfaceC1579k;
            Objects.requireNonNull(emptyList, "Argument must not be null");
            this.f2382b = emptyList;
            Objects.requireNonNull(interfaceC1590d, "Argument must not be null");
            this.f2383c = interfaceC1590d;
        }
    }

    /* renamed from: a */
    boolean mo960a(@NonNull Model model);

    @Nullable
    /* renamed from: b */
    a<Data> mo961b(@NonNull Model model, int i2, int i3, @NonNull C1582n c1582n);
}
